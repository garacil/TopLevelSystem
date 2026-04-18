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

# Module Development Guide

Step-by-step guide to creating a Portal module. For the complete API reference, see [CORE_API.md](CORE_API.md).

---

## Quick Start

### 1. Create the source file

```
modules/mod_hello/mod_hello.c
```

### 2. Write the module

```c
#include <string.h>
#include "portal/portal.h"

/* --- Descriptor --- */

static portal_module_info_t info = {
    .name        = "hello",
    .version     = "1.0.0",
    .description = "Hello world module",
    .soft_deps   = NULL
};

portal_module_info_t *portal_module_info(void) { return &info; }

/* --- Lifecycle --- */

int portal_module_load(portal_core_t *core)
{
    core->path_register(core, "/hello", "hello");
    core->path_register(core, "/hello/greet", "hello");
    core->log(core, PORTAL_LOG_INFO, "hello", "Module loaded");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/hello");
    core->path_unregister(core, "/hello/greet");
    core->log(core, PORTAL_LOG_INFO, "hello", "Module unloaded");
    return PORTAL_MODULE_OK;
}

/* --- Handler --- */

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;

    if (strcmp(msg->path, "/hello") == 0 && msg->method == PORTAL_METHOD_GET) {
        const char *text = "Hello from Portal!\n";
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, text, strlen(text) + 1);
        return 0;
    }

    if (strcmp(msg->path, "/hello/greet") == 0) {
        /* Read name from header */
        const char *name = "world";
        for (uint16_t i = 0; i < msg->header_count; i++) {
            if (strcmp(msg->headers[i].key, "name") == 0)
                name = msg->headers[i].value;
        }
        char buf[256];
        snprintf(buf, sizeof(buf), "Hello, %s!\n", name);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, strlen(buf) + 1);
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
```

### 3. Build

```bash
gcc -shared -fPIC -Wall -Wextra -Werror -std=c11 -D_GNU_SOURCE \
    -Iinclude -Isrc -Ilib/libev \
    -o modules/mod_hello.so \
    modules/mod_hello/mod_hello.c src/core/core_message.c
```

### 4. Configure

Create a config file for your module in the instance's `modules/` directory:

```
/etc/portal/<instance>/modules/mod_hello.conf
```

```ini
# mod_hello — Hello world module
enabled = true

[mod_hello]
greeting = Hello from Portal!
```

- `enabled = true` — auto-loads the module at startup
- `enabled = false` — config is loaded but module is not started
- The `[mod_hello]` section keys are accessible via `core->config_get(core, "hello", "greeting")`

**Directory structure:**
```
/etc/portal/<instance>/modules/
├── core/                    ← Infrastructure (loaded first)
│   ├── mod_cli.conf
│   ├── mod_node.conf
│   ├── mod_web.conf
│   ├── mod_ssh.conf
│   ├── mod_config_sqlite.conf
│   └── mod_config_psql.conf
└── mod_hello.conf           ← Application modules
```

### 5. Load manually (optional)

```
portal> module load hello
portal> ls /hello
portal> module list
```

---

## Module Anatomy

Every module is a `.so` file that exports 4 functions:

| Symbol | Purpose |
|--------|---------|
| `portal_module_info()` | Return module name, version, description, soft deps |
| `portal_module_load(core)` | Initialize: register paths, open resources |
| `portal_module_unload(core)` | Cleanup: unregister paths, free resources |
| `portal_module_handle(core, msg, resp)` | Handle incoming messages |

### File Naming

```
mod_<name>.so
```

The `<name>` must match `info.name`. Examples: `mod_cli.so`, `mod_db.so`, `mod_web.so`.

---

## Handling Messages

Your `portal_module_handle()` receives every message routed to your paths. Dispatch based on `msg->path` and `msg->method`:

```c
int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    if (strcmp(msg->path, "/mymod/items") == 0) {
        switch (msg->method) {
        case PORTAL_METHOD_GET:
            /* Return list of items */
            break;
        case PORTAL_METHOD_SET:
            /* Create/update an item (data in msg->body) */
            break;
        default:
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
```

### Reading Input

| Source | How to read |
|--------|------------|
| Path | `msg->path` — which resource |
| Method | `msg->method` — what action |
| Headers | Loop `msg->headers[0..header_count-1]` for key-value metadata |
| Body | `msg->body` (raw bytes), `msg->body_len` (length) |
| Auth | `msg->ctx->auth.user`, `msg->ctx->auth.labels` |

### Writing Output

```c
portal_resp_set_status(resp, PORTAL_OK);
portal_resp_set_body(resp, data, data_len);
```

Always set `resp->status`. Body is optional.

---

## Talking to Other Modules

Modules communicate via `core->send()`:

```c
portal_msg_t *msg = portal_msg_alloc();
portal_resp_t *resp = portal_resp_alloc();

portal_msg_set_path(msg, "/db/users");
portal_msg_set_method(msg, PORTAL_METHOD_GET);
portal_msg_add_header(msg, "id", "42");

int rc = core->send(core, msg, resp);
if (rc == 0 && resp->status == PORTAL_OK) {
    /* resp->body has the data */
}

portal_msg_free(msg);
portal_resp_free(resp);
```

**Important:** Always free both `msg` and `resp` when done.

---

## Soft Dependencies

Declare what you'd like (not what you require):

```c
static const char *deps[] = {"db", "cache", NULL};

static portal_module_info_t info = {
    .name      = "api",
    .version   = "1.0.0",
    .description = "REST API module",
    .soft_deps = deps
};
```

Check before using:

```c
if (core->module_loaded(core, "db")) {
    core->send(core, db_msg, db_resp);
} else {
    portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
    portal_resp_set_body(resp, "Database unavailable\n", 21);
}
```

---

## Access Control

Restrict paths with labels in `load()`:

```c
/* Public — anyone */
core->path_register(core, "/api/public", "api");

/* Admin only */
core->path_register(core, "/api/admin", "api");
core->path_add_label(core, "/api/admin", "admin");

/* Admin or dev */
core->path_register(core, "/api/debug", "api");
core->path_add_label(core, "/api/debug", "admin");
core->path_add_label(core, "/api/debug", "dev");
```

The core enforces this automatically. Your handler only receives messages that passed the ACL check.

---

## Async I/O

For sockets, serial ports, files, or any fd-based I/O:

```c
static void on_data(int fd, uint32_t events, void *userdata)
{
    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n <= 0) {
        core->fd_del(core, fd);
        close(fd);
        return;
    }
    /* process buf[0..n-1] */
}

int portal_module_load(portal_core_t *core)
{
    int fd = open("/dev/ttyS0", O_RDONLY);
    core->fd_add(core, fd, EV_READ, on_data, NULL);
    /* ... */
}
```

**Events:** `EV_READ`, `EV_WRITE` (from embedded libev, cross-platform).

---

## Using Core Paths

Your module can use built-in core services:

```c
/* List all paths */
portal_msg_set_path(msg, "/core/paths");
portal_msg_set_method(msg, PORTAL_METHOD_GET);

/* List paths under a prefix */
portal_msg_set_path(msg, "/core/ls");
portal_msg_add_header(msg, "prefix", "/mymod");

/* Check status */
portal_msg_set_path(msg, "/core/status");

/* Resolve a relative path */
portal_msg_set_path(msg, "/core/resolve");
portal_msg_add_header(msg, "cwd", "/mymod");
portal_msg_add_header(msg, "target", "../other");
```

See [CORE_API.md](CORE_API.md) Section 7 for the full list.

---

## Checklist (10 Laws Compliance)

Before releasing a module:

**Basic:**
- [ ] Exports exactly 4 symbols
- [ ] `info.name` matches the `.so` filename (`mod_<name>.so`)
- [ ] All paths registered in `load()`, unregistered in `unload()`
- [ ] All fds registered in `load()`, removed in `unload()`
- [ ] All memory allocated in `load()`, freed in `unload()`
- [ ] Uses `core->log()` for all output
- [ ] Uses `core->fd_add()` for all I/O
- [ ] Checks `module_loaded()` before using soft deps
- [ ] Sets `resp->status` in every handler path
- [ ] Compiles with `-Wall -Wextra -Werror`

**Law 8 — Resource Properties:**
- [ ] Every `path_register()` followed by `path_set_access()`
- [ ] Resources use `PORTAL_ACCESS_READ`
- [ ] Functions use `PORTAL_ACCESS_RW`
- [ ] Labels set on restricted paths

**Law 9 — Module Authentication:**
- [ ] Module can read `[mod_name] user=` and `key=` from config
- [ ] Default: runs as root if no credentials

**Law 10 — Everything Is an Event:**
- [ ] `event_emit()` called on every state change (set, del, create, send, etc.)
- [ ] Events registered with `event_register()` in `load()`
- [ ] CLI commands available for all module resources and functions
- [ ] CLI commands registered via `portal_cli_register()` in `load()`, unregistered in `unload()`

**Documentation:**
- [ ] Header comment on source file describing purpose
- [ ] All paths follow convention: `/<module>/resources/` and `/<module>/functions/`

---

## Remote Shell (dial-back channel)

Interactive terminal access to any peer via a **dedicated TLS connection
the target opens back to the initiator**. Real PTY, real PAM auth, zero
federation worker burn.

```
portal:/> shell              # Local — forkpty direct, no network
portal:/> shell <peer_name>  # Remote — dial-back TLS channel
Connected to <peer_name> (Ctrl-] to disconnect)

<peer> login: monitor
Password:                     ← /bin/su + PAM against /etc/shadow
[monitor@peer ~]$
```

### How It Works

Federation carries only a one-shot signal (`/shell/functions/dialback_request`
with a random 32-byte `session_id`). The target spawns a pthread that
opens a fresh TCP+TLS connection to the initiator's `shell_port`
(default `2223`), announces the session_id, forks a PTY, drops
privileges to `nobody`, and runs `/bin/su -l <user>`. All shell data
flows over that private TLS connection — never through the federation
worker pool.

- **Local** (`shell`): `mod_cli` forks a PTY directly, relay thread (PTY ↔ client fd).
- **Remote** (`shell <peer>`): `mod_shell.open_remote` generates a session, signals the peer through federation, waits for the dial-back, hands the resulting bridge fd to the CLI. The target's `dialback_thread` does TCP + TLS + PAM auth via `/bin/su` + PTY relay on its own pthread.

See [`modules/mod_shell/README.md`](../modules/mod_shell/README.md) for the full protocol, security model, thread breakdown, and operational notes.

### Why not `/bin/login`

util-linux 2.40+ rejects `forkpty()`-allocated PTYs with `FATAL: bad tty`. `/bin/su` uses the same PAM stack (`account`, `auth`, `session`) without that restriction, so it works cleanly on any kernel PTY. Operators who have a getty-style wrapper and want `/bin/login` back can override `shell_login_binary` in config.

### Why drop privileges before `/bin/su`

Portal runs as root. `/bin/su` is SUID root; when invoked from root, PAM's `pam_rootok` lets it skip password auth entirely. The target-side PTY child must `setuid(nobody)` before exec so that PAM goes all the way through the auth stack. If the privilege drop fails, the login aborts — exec'ing `su` as root would be an unauthenticated root shell.

### Configuration (`mod_shell.conf`)

```ini
enabled = true
[mod_shell]
# Legacy message-based API (scripts/automation)
timeout = 10         # Max seconds per stateless command
shell = /bin/sh      # Shell for /shell/functions/{exec,open}
allow_exec = true
max_output = 65536
session_ttl = 3600

# Dial-back channel (CLI shell <peer>)
shell_port           = 2223           # TLS listener port (0 = disabled)
shell_bind           = 0.0.0.0
shell_tls_cert       =                # Default: instance federation cert
shell_tls_key        =                # Default: instance federation key
shell_advertise_host =                # Host the target dials back to
shell_login_binary   = /bin/su        # What runs after privilege drop
shell_dial_timeout   = 10             # Seconds to wait for dial-back
access_label         = root           # Group required on all shell paths
```

The initiator must have `shell_port` open in its firewall. The target does not need any inbound rules — it only opens outbound connections. NAT'd / private-only devices work without port forwarding.

### CLI Help System

Every registered path can have a description:

```c
core->path_register(core, "/mymod/functions/action", "mymod");
core->path_set_access(core, "/mymod/functions/action", PORTAL_ACCESS_RW);
core->path_set_description(core, "/mymod/functions/action",
    "Does something useful. Header: param_name (required)");
```

Users discover it with:
```
portal:/> help /mymod/functions/action
portal:/> help mymod
portal:/> help get
```
