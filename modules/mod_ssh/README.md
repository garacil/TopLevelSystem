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

# mod_ssh — SSH Server for Portal CLI

Provides SSH access to the Portal CLI using any standard SSH client (OpenSSH, PuTTY, etc.). Authentication uses Portal's own user/password system. After login, the user gets the full interactive CLI — same as `portal -n <name> -r`.

## Quick Start

```bash
ssh -p 2220 root@host
Password: <portal_root_password>

Portal v1.0.0 SSH CLI
Logged in as root

Portal v1.0.0 CLI
Type 'help' for available commands.
portal:/> status
Portal v1.0.0
Status: running
Modules loaded: 50
portal:/> shell ssip888
Connected to ssip888 (Ctrl-] to disconnect)
root@ssipdev:~# htop
```

## How It Works

1. SSH client connects to mod_ssh (libssh server)
2. Password authentication against Portal's `/auth/login` path
3. mod_ssh opens a UNIX socket connection to the local CLI (mod_cli)
4. Sends `__winsize <rows> <cols>` with the SSH client's terminal dimensions
5. Auto-login on CLI with the authenticated user's credentials
6. Bidirectional bridge: SSH channel <-> CLI socket
7. Window-change events forwarded as `__winsize` for live terminal resize

## Terminal Size

- PTY dimensions captured from the SSH client's PTY request
- Sent as `__winsize` to mod_cli before any commands
- Window-change (SIGWINCH) events forwarded in real-time
- `shell` command and `htop`/`top` fill the full terminal

## Configuration

```ini
# mod_ssh.conf
enabled = true

[mod_ssh]
port = 2220                                    # SSH listen port
host_key = /etc/portal/<instance>/certs/ssh_host_key  # RSA host key (auto-generated if missing)
```

## Paths

| Path | Access | Description |
|------|--------|-------------|
| `/ssh/resources/status` | READ | SSH server status: port, host key, state |

## Security

- Authentication via Portal's user system (same users as CLI/HTTP)
- Host key auto-generated on first start (RSA 2048-bit)
- Each SSH session runs in a dedicated thread
- CLI socket auto-login uses the SSH-authenticated credentials
- Password cleared from memory after use

## Usage Examples

```bash
# Interactive CLI
ssh -p 2220 root@10.200.1.74

# All CLI commands work: status, help, top, shell, get, ls, etc.
# Shell mode (remote PTY) works with full terminal support
# Ctrl+D to disconnect
```

## Firewall

Port must be open in iptables:

```bash
iptables -A INPUT -p TCP --dport 2220 -j ACCEPT
```

Add to `/etc/init.d/firewall` for persistence.
