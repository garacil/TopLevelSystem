<!--
  Author: Germán Luis Aracil Boned <garacilb@gmail.com>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, see <https://www.gnu.org/licenses/>.
-->

# mod_shell — Remote Interactive Shell

`mod_shell` provides two independent shell subsystems that share a single
module but solve different problems:

1. **Dial-back shell channel** — what `shell <peer>` in the CLI uses today.
   A dedicated TCP+TLS connection between initiator and target carries
   raw PTY bytes; the **target device is the one that dials back** to the
   initiator on a configurable port, so NAT and firewall rules on the
   device side never need to accept inbound connections. Authentication
   happens on the target via `/bin/su -l <user>` after a privilege-drop
   step, so PAM (`pam_unix` against `/etc/shadow` by default) enforces
   the password.
2. **Legacy message-based PTY** — HTTP/API driven `open` / `write` /
   `read` / `close` paths for scripts and automation that need a shell
   without holding an interactive TCP connection. Same module, different
   use case.

The two are orthogonal. The dial-back channel is the canonical way to
get an interactive shell on a peer; the message-based API is kept for
non-interactive automation.

---

## Dial-back Shell Channel — the new path

### Why

The old `shell <peer>` command routed through `mod_node`
(`/node/functions/shell` → `/tunnel/shell`), borrowing a worker from the
federation pool as a raw byte transport. That came with three real
problems:

- **Worker-pool burn**: each shell permanently took a pool worker out
  of rotation (the fd was in raw-bytes mode, not PORTAL02-framed any
  more). After `worker_count` shells, the peer looked "unavailable"
  until the pool was rebuilt by a reconnect cycle.
- **Federation disruption**: rebuilding the pool meant tearing down and
  re-establishing the entire ctrl+workers connection. Ongoing reports,
  notifications, and `get_db` requests to that peer paused during the
  cycle.
- **Unauthenticated `root`**: the remote side ran `execl("/bin/bash",
  "bash", "-l")` directly — whoever could reach the federation socket
  got a root shell with no password.

The dial-back channel addresses all three.

### Flow

```
 INITIATOR (Portal running the CLI)         TARGET (remote peer)
 ────────────────────────────────────────────────────────────────
  shell <peer>
    │ 1. open_remote:
    │     • generate 32-byte random
    │       session_id (hex, from
    │       OpenSSL RAND_bytes)
    │     • register pending entry
    │     • send
    │       /<peer>/shell/functions/dialback_request
    │       via federation       ─────────▶
    │       (one small signal;
    │        NO shell data flows
    │        through federation)     2. handle_dialback_request
    │     • wait on condvar             spawns a new pthread
    │       (shell_dial_timeout)        (dialback_thread)
    │                                     │
    │                                     │ 3. connect() to
    │                                     │    reply_host:reply_port
    │                                     │    (blocking, own thread)
    │                                     │ 4. SSL_connect (TLS 1.2+)
    │                                     │ 5. SSL_write session_id + '\n'
    │                                     │
    │   6. listener_thread accept()       │
    │   7. accept_handler_thread:         │
    │      • SSL_accept                   │
    │      • SSL_read session_id ◀────────┘
    │      • pending_take(id) → match
    │      • socketpair(plain, tls_bridge)
    │      • hand plain side to waiter
    │      • run tls_plain_relay
    │        on its own pthread
    │
    │ 8. open_remote returns
    │    plain fd to CLI as
    │    response body
    │
  Connected to <peer>                 9. forkpty + child:
  (CLI relays user terminal ↔             • print "<host> login: "
   plain fd; accept_handler_thread        • read username (alnum._-)
   relays plain ↔ TLS fd; target's        • setgid/setuid to nobody
   dialback_thread relays TLS ↔           • execl /bin/su -l <user>
   PTY master)                              (su is SUID root, so it
                                             validates via PAM and
                                             drops to the target user)
                                           • PAM prompts password
                                           • su runs user's login shell
                                           • writes utmp/wtmp
                                        10. tls_plain_relay:
                                             PTY master ↔ TLS fd
                                             (its own pthread)

                                        Either side closes → both
                                        pthreads exit cleanly; the
                                        session_id is one-shot and
                                        cannot be reused.
```

### Paths registered by the dial-back channel

| Path | Who calls it | Purpose |
|---|---|---|
| `/shell/functions/open_remote` | CLI locally (`shell <peer>`) | Generate session, signal peer, wait for dial-back, return bridge fd |
| `/shell/functions/dialback_request` | Remote initiator via federation | Spawn dialback_thread → TCP+TLS back to initiator + run login |

Both carry the `access_label` set in config (default `root`).

### Threads per session

| Thread | Side | Lifetime |
|---|---|---|
| `listener_thread` | Initiator | One for the module; `accept()` loop |
| `accept_handler_thread` | Initiator | One per dial-back; TLS handshake, session lookup, then runs `tls_plain_relay` |
| `dialback_thread` | Target | One per incoming request; TCP/TLS/PTY fork + `tls_plain_relay` |

Each thread cleans up its own resources on exit. The Portal event loop
is never touched for shell data; only the one-shot signal message uses
federation.

### Security model

The target-side PTY child does the following **before** execing
`/bin/su`:

1. Prompt `"<hostname> login: "` on its stdout (= PTY slave).
2. Read a username from stdin one byte at a time, accepting only
   `[A-Za-z0-9._-]` (the POSIX portable username set), capped at 32
   characters, with backspace handling.
3. Validate the resulting buffer a second time defensively.
4. **Drop privileges** — `setgroups(0, NULL)`, `setgid(nobody_gid)`,
   `setuid(nobody_uid)`. If the drop fails, abort the login (do NOT
   continue as root; see below).
5. Close any inherited fds ≥ 3 (Portal internal sockets must not leak
   into the login shell).
6. `execl("/bin/su", "su", "-l", user, NULL)`.

Why drop to `nobody` before `/bin/su`:

- `/bin/su` is SUID root. When invoked from root (euid 0), PAM's
  `pam_rootok.so` lets `su` skip the password prompt entirely — a root
  caller is trusted to know what it's doing. If we didn't drop
  privileges, a user typing any valid username + Enter would land in a
  shell with no password check: a full remote unauthenticated privilege
  escalation.
- As `nobody` we lose the root-trust exemption, so `/bin/su` goes all
  the way through the PAM auth stack (`pam_unix` → `/etc/shadow`) and
  only becomes the target user after a correct password.

Why we refuse to continue if `setuid/setgid` fails: exec'ing `su` while
still root is exactly the vulnerability the drop is defending against.
A failed drop is a hard stop; the dial-back session closes cleanly and
the user sees an error.

The password itself is read by `/bin/su` directly from the PTY slave
(stdin) with echo disabled — we never see it, never buffer it, never
log it.

TLS:

- Both server (initiator's listener) and client (target's dial-back
  socket) use OpenSSL ≥ TLS 1.2.
- The cert/key default to the instance's shared federation cert
  (`node.cert_file` / `node.key_file`), so operators don't need a
  separate PKI for this channel — but `shell_tls_cert` / `shell_tls_key`
  can override.
- Peer cert verification is OFF by default (`SSL_VERIFY_NONE`). The
  per-session nonce (32 bytes of `RAND_bytes`, sent as the first line
  after TLS handshake) is what actually authenticates the channel. A
  pending session can only be consumed once and only within
  `shell_dial_timeout` seconds; otherwise `pending_take` returns NULL
  and the handler logs a warning + drops the connection.

### Quick start

```
portal:/> shell ssip867
Connected to ssip867 (Ctrl-] to disconnect)

ssip867 login: monitor
Password:              ← /bin/su + PAM, we never see it
[monitor@ssip867 ~]$ whoami
monitor
[monitor@ssip867 ~]$ exit
Session ended
portal:/>
```

---

## Configuration

File: `/etc/portal/<instance>/modules/mod_shell.conf`

```ini
enabled = true

[mod_shell]
# ── Legacy message-based PTY ──
timeout        = 10          # Max seconds for /shell/functions/exec
shell          = /bin/sh     # Used by /shell/functions/exec + /open
allow_exec     = true        # Hard safety switch for exec path
max_output     = 65536       # Max bytes per read() on API sessions
session_ttl    = 3600        # Auto-close idle API PTY sessions (seconds)
access_label   = root        # Group label required for all shell paths

# ── Dial-back shell channel ──
shell_port           = 2223                    # Listener port (0 = disabled)
shell_bind           = 0.0.0.0                 # Bind address (LAN/overlay only if preferred)
shell_tls_cert       =                         # Default: instance federation cert
shell_tls_key        =                         # Default: instance federation key
shell_advertise_host =                         # Host/IP the target dials back to;
                                               # empty = first non-loopback IPv4 (guess).
                                               # Set explicitly on multi-homed hosts.
shell_login_binary   = /bin/su                 # /bin/login DOES NOT WORK — see note
shell_dial_timeout   = 10                      # Max seconds to wait for dial-back (1-60)
```

### Why not `/bin/login`

util-linux 2.40+ (AlmaLinux 10, recent Debians) runs `check_tty()` at
startup and rejects any PTY not allocated by getty with `FATAL: bad
tty`. `forkpty` + `execl("/bin/login")` hits this immediately, and the
session drops on the first keystroke. `/bin/su` uses the same PAM
stack (`account`, `auth`, `session` from `system-auth`) but has no
TTY-origin restrictions, so it works on any PTY the kernel will give
us.

If a deployment has a getty-style wrapper and wants `/bin/login` back,
override `shell_login_binary`.

### `shell_advertise_host`

The target must be able to `connect()` to
`<shell_advertise_host>:<shell_port>`. Portal's auto-detect picks the
first non-loopback IPv4 from `getifaddrs()`, which on multi-homed
hosts may be the wrong interface (e.g., a public WAN IP when the
target reaches you only over LAN or a WireGuard overlay). Examples:

```ini
# futurepbx devtest — reachable from ssip-hub over LAN
shell_advertise_host = 192.168.1.198

# core.tucall.com hub — reachable from ssip867 over public internet
shell_advertise_host = 213.162.195.20

# An SSIP appliance — reachable only on the WG overlay
shell_advertise_host = 10.200.1.79
```

### Firewall

The initiator must accept inbound TCP on `shell_port`. On core1
(AlmaLinux with `/etc/init.d/firewall`) that means an explicit
`iptables -A INPUT -p TCP --dport 2223 -j ACCEPT`. The target side
never needs to accept inbound — it only opens outbound connections, so
NAT'd devices work without any port-forwarding.

---

## Legacy Message-based PTY (kept for automation)

The original API remains registered and functional. Useful for HTTP
clients and scripts that can't hold an interactive TCP:

```bash
# Stateless exec
curl -u root:<pass> -X PUT "http://host:8080/api/shell/functions/exec?cmd=hostname"

# Long-lived PTY session
SID=$(curl -s -u root:<pass> -X PUT "http://host:8080/api/shell/functions/open?rows=24&cols=80")
curl -s -u root:<pass> -X PUT "http://host:8080/api/shell/functions/write?session=$SID" -d "ls -la"
curl -s -u root:<pass> -X PUT "http://host:8080/api/shell/functions/read?session=$SID"
curl -s -u root:<pass> -X PUT "http://host:8080/api/shell/functions/close?session=$SID"
```

| Path | Access | Headers | Description |
|---|---|---|---|
| `/shell/functions/exec` | RW (`access_label`) | `cmd`, `cwd`, `timeout` | Stateless popen |
| `/shell/functions/open` | RW (`access_label`) | `rows`, `cols` | Allocate PTY, returns `session_id` |
| `/shell/functions/write` | RW (`access_label`) | `session` + raw body | Write to PTY |
| `/shell/functions/read` | RW (`access_label`) | `session` | Read available output |
| `/shell/functions/close` | RW (`access_label`) | `session` | Terminate |
| `/shell/functions/resize` | RW (`access_label`) | `session`, `rows`, `cols` | `ioctl(TIOCSWINSZ)` |

The legacy path runs `g_cfg.shell` (default `/bin/sh`) **as root** —
it's assumed the caller has already authenticated via Portal's
`/auth/login` and has the `access_label` group. Use only on trusted
control planes.

---

## Events

| Event | When |
|---|---|
| `/events/shell/exec` | Stateless command executed (legacy) |
| `/events/shell/session` | Legacy PTY session opened/closed |

The dial-back path logs informational lines via `core->log` but does
not emit separate events today — every dial-back appears in the main
Portal log with the session_id prefix (first 8 hex chars) for
correlation.

---

## Operational notes

- The dial-back listener is **disabled if `shell_port = 0`**. Useful
  for Portal instances that should never initiate outbound shells
  (e.g., a secondary test instance that only needs the target role —
  set `shell_port = 0` there, the target-side `dialback_request`
  handler is still registered and works).
- Two Portal instances on the same host need different `shell_port`
  values or one of them set to 0 — the bind otherwise fails with
  `Address already in use` and the listener silently stays disabled
  (the target-side handler still works, but `open_remote` refuses
  with `listener not enabled`).
- On restart the listener re-binds `shell_port` and re-loads the TLS
  context; in-flight sessions die cleanly because their dedicated
  pthreads see EOF on their fds.

---

*Copyright (c) 2026 — 7kas servicios de internet SL*
