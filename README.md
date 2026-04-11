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

# Portal v1.0.0

**Universal Modular Core** — A minimal C microkernel that connects hot-loadable modules through path-based message routing. Everything is a path. Every interaction is a message.

---

## Table of Contents

- [Quick Start](#quick-start)
- [What is Portal?](#what-is-portal)
- [Interfaces](#interfaces)
- [HTTP REST API](#http-rest-api)
- [CLI Reference](#cli-reference)
- [Authentication](#authentication)
- [Architecture](#architecture)
- [Modules](#modules)
- [Federation](#federation)
- [Storage](#storage)
- [Configuration](#configuration)
- [Named Instances](#named-instances)
- [Creating Modules](#creating-modules)
- [Source Code](#source-code)
- [Stats](#stats)

---

## Quick Start

```bash
# Build
make                        # Compile core + 51 modules + tools
make tests                  # Run 57 unit tests
make install                # Install to /usr/local/bin + /usr/lib/portal

# Instance management
portal -C myapp             # Create instance (auto: ports, certs, users, 48 module configs)
portal -D myapp             # Delete instance (stops, removes everything)
portal -s                   # Show status of all instances

# Start
portal -n myapp -f -d       # Foreground with debug
systemctl start portal-myapp # Or via systemd

# Connect
portal -n myapp -r           # CLI (arrow keys, tab completion, history)
http://HOST:PORT/api         # HTTP REST API (port shown at creation)
https://HOST:PORT/api        # HTTPS
http://HOST:PORT/api/admin/dashboard  # Web admin panel
```

---

## What is Portal?

Portal is a core that does almost nothing by itself. It loads modules, routes messages between them via paths, and manages their lifecycle. Web servers, database connectors, serial port readers, AI agents, node federation — everything is a module.

```
portal (core)
  ├── mod_cli.so              CLI over UNIX socket (shell-like navigation)
  ├── mod_node.so             TCP federation between Portal instances
  ├── mod_web.so              HTTP/HTTPS REST API gateway
  ├── mod_config_sqlite.so    SQLite storage backend (transparent)
  ├── mod_config_psql.so      PostgreSQL storage backend (transparent)
  ├── mod_hello.so            Hello world example module
  ├── mod_myapp.so            Example app (counter, events, ACL demo)
  └── (your module here)      Build anything — same interface for all
```

The core provides:
- **Path-based routing** with O(1) hash table + wildcard fallback
- **Universal message system** — one structure for all communication
- **Label-based ACL** — groups on users, labels on paths, intersection = access
- **Hot-loadable modules** — load, unload, reload at runtime with reference counting
- **Cross-platform event loop** — embedded libev (epoll/kqueue/select)
- **Module crash isolation** — core survives module segfaults (setjmp/longjmp)
- **Message tracing** — trace_id, timestamp, hop count on every message
- **Pub/Sub events** — ACL-controlled event subscriptions with pattern matching

---

## Interfaces

Portal exposes its path system through 6 simultaneous interfaces. All share the same paths, same ACL, same data:

| Interface | Protocol | Default Port | Description |
|-----------|----------|-------------|-------------|
| **CLI** | UNIX socket | — | Interactive shell with arrow key history |
| **HTTP** | HTTP/1.1 | 8080 | REST API: `GET /api/path` |
| **HTTPS** | TLS | 8443 | Encrypted REST (self-signed or custom certs) |
| **Core TCP** | Wire protocol | 9800 | Binary protocol for direct integration |
| **Core UDP** | Wire protocol | 9800 | Stateless binary protocol |
| **Node TCP** | Wire protocol | 9701 | Federation between Portal instances |

All ports are configurable per instance. Set to 0 to disable.

---

## HTTP REST API

Every Portal path is accessible as an HTTP endpoint. Browse the auto-generated index:

```
http://192.168.1.198:8080/api       ← Full API index (auto-generated from live paths)
http://192.168.1.198:8080/api/      ← Same
```

### Module Management (from browser!)

```
http://host:8080/api/core/modules                           List modules
http://host:8080/api/core/modules/myapp?action=load         Load module
http://host:8080/api/core/modules/myapp?action=unload       Unload module
http://host:8080/api/core/modules/myapp?action=reload       Reload module
```

### Example: myapp Module (load → use → unload from browser)

```
1. http://host:8080/api/core/modules/myapp?action=load           → "load OK"
2. http://host:8080/api/myapp/resources/status                    → version, counter, deps
3. http://host:8080/api/myapp/functions/increment?action=call     → Counter: 1
4. http://host:8080/api/myapp/functions/increment?action=call     → Counter: 2
5. http://host:8080/api/myapp/resources/counter                   → 2
6. http://host:8080/api/core/modules/myapp?action=unload          → "unload OK"
7. http://host:8080/api/core/modules/myapp?action=load            → "load OK" (counter resets)
```

### Core Endpoints

```bash
GET /api/core/status                # Portal version, modules, paths count
GET /api/core/modules               # List loaded modules with versions
GET /api/core/paths                 # All registered paths
GET /api/core/storage               # Active storage backends
GET /api/core/ls?prefix=/           # List children at any path
GET /api/core/ls?prefix=/core       # List core sub-paths
```

### User Management

```bash
GET  /api/users                     # List all users + groups
GET  /api/users/admin               # User info (groups, API key status)
POST /api/users/newuser?password=x  # Create user
PUT  /api/users/admin/password?password=newpass  # Change password
```

### Group Management

```bash
GET  /api/groups                    # List all groups + member counts
GET  /api/groups/admin              # Group info + members
POST /api/groups/ops                # Create group
PUT  /api/groups/ops/add?user=bob   # Add user to group
PUT  /api/groups/ops/remove?user=bob # Remove user from group
```

### Authentication

```bash
# Three auth methods supported:

# 1. API Key (query parameter)
GET /api/users?api_key=YOUR_64CHAR_HEX_KEY

# 2. Bearer Token (header)
curl -H "Authorization: Bearer YOUR_TOKEN" http://host:8080/api/users

# 3. HTTP Basic Auth (browser-native login prompt)
curl -u admin:admin http://host:8080/api/users
# Browser will show login dialog automatically
```

### Node Federation

```bash
GET /api/node/resources/status      # This node's name, port, TLS, peer count
GET /api/node/resources/peers       # Connected peers with traffic stats
GET /api/node/resources/peer/asus   # Detailed peer status (TLS, workers, counters)
PUT /api/node/functions/ping?name=asus    # Measure RTT to peer
PUT /api/node/functions/ping?name=all     # Ping all peers
PUT /api/node/functions/trace?path=/asus/core/status  # Traceroute through federation

# Access remote node resources transparently:
GET /api/devtest2/core/status       # Status of remote node "devtest2"
GET /api/asus/iot/resources/devices  # IoT devices on remote NAT node (via hub)
```

### Events & Storage

```bash
GET /api/events                     # List registered events
GET /api/core/storage               # Active backends (file, sqlite, psql)
GET /api/core/storage/sqlite/resources/status  # SQLite details
GET /api/core/storage/psql/resources/status    # PostgreSQL details
GET /api/web/resources/status       # HTTP module status
```

### HTTP Method Mapping

| HTTP Method | Portal Method | Use for |
|-------------|--------------|---------|
| `GET` | `PORTAL_METHOD_GET` | Read a resource |
| `POST` | `PORTAL_METHOD_SET` | Create or update |
| `PUT` | `PORTAL_METHOD_CALL` | Execute an action |
| `DELETE` | `PORTAL_METHOD_CALL` | Delete (action=delete) |

---

## CLI Reference

Connect with `portal -n devtest -r` or `portalctl -s /var/run/portal-devtest.sock`.

### Navigation

| Command | Description |
|---------|-------------|
| `ls [path]` | List children (shows users, groups, modules, remote nodes) |
| `cd <path>` | Change current path |
| `pwd` | Print current path |
| `get <path>` | Send GET to any path and display response |

### System

| Command | Description |
|---------|-------------|
| `status` | Portal version, module count, path count |
| `storage` | Active storage backends |
| `module list` | All loaded modules with versions |
| `module load <name>` | Hot-load a module |
| `module unload <name>` | Unload (waits for active calls to finish) |
| `module reload <name>` | Atomic unload + load |
| `events` | List registered events |
| `subscribe <path>` | Subscribe to event notifications |
| `unsubscribe <path>` | Remove subscription |

### Authentication

| Command | Description |
|---------|-------------|
| `login <user> [pass]` | Authenticate |
| `logout` | End session |
| `whoami` | Show current user and groups |
| `passwd <newpass>` | Change own password |
| `key` | Show API key |
| `key rotate` | Generate new API key |

### User & Group Management

| Command | Description |
|---------|-------------|
| `user list` | All users with groups |
| `user info <name>` | User details |
| `user create <name> <pass>` | Create user |
| `user passwd <name> <pass>` | Change any user's password (admin) |
| `group list` | All groups with member counts |
| `group info <name>` | Group details + members |
| `group create <name>` | Create group |
| `group adduser <group> <user>` | Add user to group |
| `group deluser <group> <user>` | Remove user from group |

### Module Shortcuts

| Command | Description |
|---------|-------------|
| `cache set <k> <v> [ttl]` | Set cache key |
| `cache get <key>` | Get cache value |
| `cache del <key>` | Delete cache key |
| `cache flush` | Clear all cache |
| `cron add <n> <s> <p>` | Schedule recurring job (name, interval_secs, path) |
| `cron jobs` | List scheduled jobs |
| `kv set <k> <v>` | Set persistent key-value |
| `kv get <key>` | Get persistent value |
| `kv del <key>` | Delete persistent key |
| `kv keys` | List all keys |
| `firewall deny <src>` | Block a source |
| `firewall allow <src>` | Allow a source |
| `firewall check <src>` | Check if blocked |
| `firewall rules` | Show all rules |
| `dns resolve <host>` | Resolve hostname |
| `dns reverse <ip>` | Reverse DNS |
| `backup create [name]` | Create backup |
| `backup list` | List backups |
| `schedule <n> <s> <p>` | One-shot task (name, delay_secs, path) |
| `schedule list` | List scheduled tasks |
| `process exec <cmd>` | Execute system command (admin) |
| `validate email <v>` | Validate email |
| `validate ip <v>` | Validate IP address |
| `config get <mod> <key>` | Get module config value |
| `config set <mod> <k> <v>` | Set module config (persists to DB) |
| `config list [module]` | List all module config values |
| `sysinfo` | System information |
| `metrics` | CPU, memory, disk, load |
| `health` | Module health check |
| `json <path>` | Get any path as JSON |
| `curl <url>` | HTTP GET external URL |
| `ping [name\|all]` | Measure RTT to peer(s) |
| `tracert <path>` | Traceroute to a path through federation |
| `node peers` | Show connected peers with traffic stats |
| `node status <name>` | Detailed peer status (TLS, workers, counters) |
| `node ping [name\|all]` | Alias for `ping` |
| `node trace <path>` | Alias for `tracert` |
| `iot discover <subnet> [brand]` | Scan LAN for IoT devices |
| `iot devices` | List all devices (name, model, state, MAC) |
| `iot status [name]` | Live device status via KLAP query |
| `iot refresh` | Query all devices for live state + names |
| `iot on <name>` | Turn device on |
| `iot off <name>` | Turn device off |
| `iot toggle <name>` | Toggle device state |
| `iot add <n> <ip> [drv] [brand]` | Add device manually |
| `iot remove <name>` | Remove device |
| `iot bulb brightness<N> <name>` | Set bulb brightness (1-100) |
| `iot bulb color_temp<N> <name>` | Set color temperature (2500-6500K) |
| `iot bulb hue<N>,<sat> <name>` | Set hue (0-360) and saturation (0-100) |
| `iot bulb rgb<R>,<G>,<B> <name>` | Set RGB color (doesn't change brightness) |
| `iot bulb color_<name> <name>` | Named color: red, green, blue, yellow, purple, orange, cyan, pink, white |
| `iot vacuum start <name>` | Start robot vacuum cleaning |
| `iot vacuum stop <name>` | Stop vacuum |
| `iot vacuum dock <name>` | Return vacuum to dock |
| `iot vacuum status <name>` | Vacuum status |
| `iot children <name>` | List hub child devices (sensors, cameras) |
| `verbose [filter]` | Show messages in/out in real-time (contains match) |
| `verbose off` | Stop message trace |
| `debug [filter]` | Like verbose + hex/text dump of body |
| `debug off` | Stop debug trace |
| `top` | Real-time Portal-internal viewer (modules + threads + msg/min). `q`/`ESC`/`Ctrl-C` to quit. |
| `locks` | Show all active resource locks |
| `locks <filter>` | Show locks matching path |
| `lock <resource>` | Acquire exclusive lock |
| `unlock <resource>` | Release lock |
| `node location <text>` | Set node location (free text) |
| `node gps <lat,lon>` | Set GPS coordinates |
| `node geolocate` | Auto-detect location from public IP |

### Keyboard

| Key | Action |
|-----|--------|
| Up/Down | Browse command history (64 commands) |
| Left/Right | Move cursor in line |
| Home / Ctrl+A | Jump to start |
| End / Ctrl+E | Jump to end |
| Ctrl+U | Clear line |
| Ctrl+L | Clear screen |
| Ctrl+D | Exit |
| Backspace | Delete character |

---

## Authentication

### Three Methods

1. **Username + Password** — Login via CLI or HTTP Basic Auth. Passwords stored as SHA-256 hashes or plain text (backwards compatible).

2. **API Keys** — 64-character hex strings. Alternative to passwords for automated access. Generated per user, rotatable.

3. **Session Tokens** — Returned after login. 32-character hex, TTL 1 hour (configurable). Auto-cleaned by timer.

### Label-Based Access Control

- Users have **groups** (labels): `admin`, `dev`, `finance`
- Paths have **labels**: set by modules via `core->path_add_label()`
- **Access rule**: `intersection(user.groups, path.labels) != empty` → ALLOW
- Path with **no labels** → open to everyone (public)
- **root** user → always allowed (bypasses all checks)
- ACL enforced identically across CLI, HTTP, TCP, UDP — all interfaces

### Users File

```ini
# /etc/portal/devtest/users/admin.conf
password = $sha256$salt$hash
api_key = a1b2c3d4...
groups = admin,dev
```

---

## Architecture

### Core Principles

1. **Everything is a path** — Every resource has an address
2. **Everything is a message** — One structure for all communication
3. **The core does nothing** — Modules implement all business logic
4. **No hard dependencies** — Modules degrade gracefully
5. **Hot-loadable** — Load, unload, reload at runtime
6. **One interface, universal** — Serial ports speak the same as REST APIs
7. **Nodes are peers** — Transparent federation
8. **Security is a path problem** — Labels on paths and users
9. **Observe everything** — Trace every message
10. **Simplicity is not optional** — The elegant solution is the correct one
11. **C is the foundation** — Minimal, portable, zero dependencies
12. **Fail soft, log loud** — Module crashes don't crash the core
13. **No magic** — Explicit over implicit
14. **Build for composition** — Small modules compose into systems

See [docs/PHILOSOPHY.md](docs/PHILOSOPHY.md) for the full explanation.

### Message Flow

```
Client → Interface (CLI/HTTP/TCP) → Core Router → ACL Check → Module Handler → Response
                                        ↓
                                   Trace (id, timestamp, hops)
                                        ↓
                                   Pub/Sub fan-out (if EVENT method)
```

### Core Components

| Component | File | Description |
|-----------|------|-------------|
| Path Router | `core_path.c` | O(1) hash table lookup + wildcard fallback |
| Module Loader | `core_module.c` | dlopen/dlsym, reference-counted safe unload |
| Message System | `core_message.c` | Alloc, route, free with tracing |
| Authentication | `core_auth.c` | SHA-256, API keys, sessions, TTL |
| Event Loop | `core_event.c` | libev wrapper (epoll/kqueue/select) |
| Pub/Sub | `core_pubsub.c` | Pattern matching (exact/wildcard/global) |
| Event Registry | `core_events.c` | ACL-controlled event subscriptions |
| Wire Protocol | `core_wire.c` | Binary serialization for federation |
| File Store | `core_store.c` | INI files with atomic writes |
| Multi-Storage | `core_storage.c` | Provider registry (file+sqlite+psql) |
| Config | `core_config.c` | INI parser with per-module sections |
| Handlers | `core_handlers.c` | All /core, /auth, /users, /groups paths |
| Crash Guard | `portal_instance.c` | setjmp/longjmp around module calls |

---

## Modules

### mod_cli — Command Line Interface

UNIX socket server with full line editing (arrow keys, history, Ctrl shortcuts). Clients connect via `portal -r` or `portalctl`. Per-client state: current path, auth session, command history.

### mod_node — Node Federation

Connects Portal instances into a distributed network. Worker thread pool per peer for maximum throughput. Wire protocol over TCP/TLS. Remote paths appear locally as `/<node_name>/*`. Automatic reconnection on disconnect.

Features:
- **TLS encryption** — Optional OpenSSL-based encryption for all federation traffic. Self-signed certs auto-generated by `portal -C`. Configurable cert verification.
- **Federation key** — SHA-256 shared secret authentication in handshake. Rejects peers with wrong key.
- **Hub routing** — Public node relays between NAT nodes. Peers advertise their connections during handshake. Indirect peers registered automatically. Enables NAT-to-NAT communication through a public hub.
- **PORTAL02 handshake** — Magic + key hash + node name + advertised peer list.

Diagnostics:
- `ping asus` — measure RTT to peer (22ms over TLS to NAT node)
- `tracert /asus/core/status` — show hops: local → hub → target with latency
- `node status asus` — detailed: TLS, workers, uptime, msgs/bytes sent/recv, errors
- `node peers` — all peers with traffic counters

Config: `listen_port`, `threads_per_peer`, `node_name`, `tls`, `cert_file`, `key_file`, `tls_verify`, `federation_key`

### mod_web — HTTP/HTTPS REST API

Maps HTTP requests to Portal messages. Auto-generates API index from live paths. Supports three auth methods (API Key, Bearer Token, HTTP Basic Auth). CORS enabled. Configurable bind address for LAN-only access.

Config: `port`, `tls_port`, `bind`, `api_prefix`, `cert_file`, `key_file`

### mod_config_sqlite — SQLite Storage

Transparent storage backend using a local SQLite database. Auto-creates tables on first load. WAL mode for concurrency. Receives all user/group writes alongside file storage.

Config: `database` (path to .db file)

### mod_config_psql — PostgreSQL Storage

Transparent storage backend using remote PostgreSQL. Auto-creates database and tables. Parameterized queries (SQL injection safe). Receives all user/group writes alongside file storage.

Config: `host`, `port`, `user`, `password`, `database`

All storage modules are **transparent** — they register as core storage providers and have no visible paths. The core writes to ALL active providers on every change.

### mod_ssh — SSH Server

SSH access to Portal CLI. Any standard SSH client connects and gets the full interactive CLI. Authentication uses Portal's own user/password system.

Config: `port` (default 2222)

### mod_cache — In-Memory Key-Value Store

Thread-safe hash table cache with TTL expiry. CLI: `cache set/get/del/keys/status/flush`. Emits events on set/del/flush.

### mod_health — Health Checks

Liveness/readiness probes for monitoring. Kubernetes/Docker compatible. CLI: `health`, `uptime`.

### mod_cron — Scheduled Tasks

Interval-based job scheduler. Jobs trigger path calls. CLI: `cron add/remove/trigger/jobs`. Emits events on add/remove/execute.

### mod_json — JSON Formatter

Wraps any Portal path response as JSON. CLI: `json <path>`.

### mod_http_client — HTTP/HTTPS Client

Outbound HTTP requests from any module. CLI: `curl <url>`.

### mod_shm — Shared Memory

Named POSIX shared memory regions. Create, read, write, destroy. Emits events on create.

### mod_queue — Message Queues

Thread-safe FIFO queues. Push, pop, peek. Emits events on push/pop.

### mod_websocket — WebSocket Server

Real-time push to browsers. Clients send path names, receive responses.

### mod_mqtt — MQTT Broker

Lightweight MQTT broker. Clients publish/subscribe to topics. MQTT publish → Portal event emit.

### mod_email — Email Sender

Send emails via SMTP. Configurable server, auth. Emits event on send.

### mod_logic — Logic Framework

Application logic framework. Manages scripts, routes, language handlers.

### mod_logic_lua — Lua Engine

Embedded Lua 5.4. Scripts in `/var/lib/portal/<instance>/logic/<appname>/main.lua`. Full portal API: `portal.get()`, `portal.call()`, `portal.route()`, `portal.log()`.

### mod_logic_python — Python Engine

CPython 3.11 in subprocess. Scripts in `main.py`. Same portal API: `import portal; portal.get()`.

### mod_logic_c — C Engine

Compiles `.c` files with gcc, loads via dlopen. Native speed. Scripts in `main.c`. Exports: `app_load()`, `app_handle()`, `app_unload()`.

### mod_logic_pascal — Pascal Engine

Compiles `.pas` files with fpc 3.2.2, loads via dlopen. Scripts in `main.pas`.

### mod_worker — Thread Pool

Named thread pools for background task execution. Create pools with configurable thread counts, submit jobs (path calls), track completion/failure stats. Thread-safe with proper shutdown.

### mod_serial — Serial Port

RS232/serial port communication via termios. Open, configure, read, write serial devices. Supports baud rates 1200-115200. Byte counters per port.

### mod_file — Filesystem Operations

Sandboxed file I/O within a configurable base directory. Read, write, list, delete, info, mkdir. Path traversal protection (rejects `..`). Configurable max file size.

### mod_metrics — System Metrics

Real-time system metrics from `/proc`: CPU usage, memory (total/used/free/cached/swap), disk space, load average, uptime. All read-only resources.

### mod_audit — Audit Trail

Circular buffer audit log recording all events and requests. Subscribes to `/events/*` automatically. Searchable by user or path. Optional file persistence. Admin-only clear function.

### mod_template — Template Engine

Template rendering with `{{variable}}` syntax. Load templates from files, cache in memory, render with key-value substitution. Store templates via path system or filesystem. Supports inline body templates.

### mod_proxy — Reverse Proxy

HTTP reverse proxy with named routes. Map portal paths to upstream servers. URL parsing, connection timeout, error tracking per route. Forward requests and return upstream responses.

### mod_dns — DNS Resolver

DNS utility: resolve hostnames (A/AAAA records via getaddrinfo), reverse lookup (PTR via getnameinfo), full lookup with aliases. Events on resolve/reverse operations.

### mod_firewall — Rate Limiting and IP Filtering

Source-based firewall: explicit allow/deny rules + automatic rate limiting (configurable requests per window). Check any source against rules and rate tracker. Thread-safe. Admin-only clear.

### mod_gpio — GPIO Pin Control

GPIO for IoT/embedded via Linux sysfs. Export/unexport pins, set direction (in/out), read/write values. Auto-detects hardware availability, falls back to simulation mode. Designed for Raspberry Pi, BeagleBone, etc.

### mod_process — Command Execution + Process Introspection

Sandboxed system command execution via popen. Configurable allowed command whitelist (default: ls, cat, df, free, uname, ps, etc.). Rejects dangerous patterns (rm -rf, mkfs, dd). Admin-only access.

Also exposes read-only `/proc` introspection used by the CLI `top` builtin and reachable from any client:

| Path | Returns |
|---|---|
| `/process/resources/portal_top` | Portal-internal view: process header (PID/RSS/VSize/CPU%/state), module table (name version state #paths #msgs msgs/min last), thread list with per-thread CPU% and name (from `/proc/self/task/<tid>/comm`) |
| `/process/resources/list` | All host PIDs (`pid ppid state %cpu %mem rss comm`) |
| `/process/resources/top?n=N&sort=cpu\|mem\|pid` | Top N host processes sorted |
| `/process/resources/threads?pid=N` | Threads of a target PID (default: portal's own) |
| `/process/resources/self` | Portal's PID, PPID, RSS, VSize, thread count |

CPU% is computed from a two-sample delta against `/proc/stat` total jiffies (first call returns 0%, subsequent calls show live usage). MEM% from `/proc/meminfo MemTotal`. msgs/min in `portal_top` is computed per module from a wall-clock delta against the previous sample.

### mod_kv — Persistent Key-Value Store

File-backed key-value store that survives restarts. Each key stored as a file. Thread-safe, path traversal protection. Unlike mod_cache (in-memory + TTL), mod_kv is persistent with no expiry.

### mod_webhook — Webhook Dispatcher

Register HTTP webhook URLs, auto-dispatch on Portal events. Configurable timeout and retry count. Manual send and test functions. Subscribes to `/events/*` for automatic event forwarding.

### mod_sysinfo — System Information

Read-only system details: hostname, OS/kernel version, CPU count, network interfaces (IPv4/IPv6), environment variables (admin-only). Uses uname, getifaddrs, sysconf.

### mod_crypto — Cryptographic Utilities

SHA-256 hash (embedded), MD5 hash (embedded), Base64 encode/decode, hex encode/decode. All zero-dependency, no external libraries. Verified against system sha256sum/md5sum.

### mod_log — Log Viewer

Access Portal instance logs via path system. Tail last N lines, search by pattern, list log files, rotate logs. Configurable log directory and line limits.

### mod_backup — Instance Backup/Restore

Create tar.gz backups of instance config and data. Restore from archives. List and delete backups. Admin-only operations. Events on create/restore/delete.

### mod_ldap — LDAP Authentication

Authenticate users against LDAP/Active Directory servers. Simple LDAP bind protocol (BER encoded). Configurable server, base DN, bind credentials, user filter. Connection test function.

### mod_xz — XZ/LZMA Compression

Compress/decompress data using XZ (LZMA2) via liblzma. Configurable compression level (0-9). Buffer-based API for in-memory operations. Events on compress/decompress.

### mod_gzip — Gzip Compression

Compress/decompress data using gzip (deflate) via zlib. Configurable compression level (1-9). Proper gzip header format (windowBits 15+16). Shows zlib version in status.

### mod_validator — Input Validation

Validate common formats: email, IPv4/IPv6, URL, JSON (balanced braces), number ranges, POSIX regex matching, hostnames. Returns valid/invalid with details. Stats tracking.

### mod_scheduler — One-Shot Task Scheduler

Schedule path calls at specific timestamps or after delays. Tasks execute once (complement to mod_cron intervals). Track pending/done/failed/cancelled status. Cancel pending tasks.

### mod_api_gateway — API Gateway

Route external APIs through Portal with response caching (via mod_cache), rate limiting (via mod_firewall), auth header passthrough, configurable timeout. Named routes with upstream URL mapping. Cache hits tracked per route.

### mod_acme — ACME/Let's Encrypt Certificates

Automate TLS certificate provisioning via ACME protocol. Auto-detects certbot or acme.sh, falls back to self-signed. Request certificates for domains, check expiry, auto-renew. Stores certs in instance `certs/` directory.

### mod_admin — Web Admin Dashboard

HTML admin panel with dark GitHub-inspired theme. Dashboard page shows module count, path count, memory %, load average, uptime. Module detail page with per-module status. Config viewer. Audit trail page. Served as `text/html` via mod_web at `/admin/dashboard`.

### mod_iot — IoT Device Management

Complete IoT device discovery, control, and monitoring. Supports multiple brands and protocols through built-in drivers: MQTT (Tasmota/Shelly/Sonoff/Zigbee), HTTP (Shelly/Hue), Tapo KLAP v2 (TP-Link), Tapo Hub SSL securePassthrough, GPIO.

Supported Tapo devices:
- **P100/P110 plugs** — on/off/toggle/status via KLAP v2
- **L530/L510 bulbs** — on/off + brightness, color temperature, hue/saturation, RGB, named colors
- **H100 hub** — child device listing (sensors, cameras) via SSL securePassthrough
- **RV30 vacuum** — start/stop/dock/status via SSL securePassthrough (port 443/4433)
- **T315 sensor** — temperature/humidity via H100 hub child devices

Discovery: ARP scan + MAC vendor identification + KLAP handshake probe (finds Tapo devices even with unknown MAC). Base64 nickname decoding from Tapo app. Background refresh.

Config: `max_devices`, `poll_interval`, `tapo_email`, `tapo_password`

### mod_tunnel — Port Forwarding Through Federation

Raw TCP port forwarding through federation connections. Export local services, map remote services to local ports. Zero-overhead byte relay using select() pipe after initial wire-protocol handshake. Enables SSH, HTTP, or any TCP service access across NAT through the federation hub.

Config: exports and maps persisted to instance `tunnel/` directory.

### mod_watchdog — Hardware Watchdog Keepalive

Opens `/dev/watchdog` and writes a keepalive byte at a configurable interval. If Portal stops, the hardware timer expires and the system reboots — essential for unattended embedded/appliance devices. Exclusive resource locking (Law 14) prevents conflicts. Magic close (`V`) on disable/unload disarms cleanly without reboot.

Config: `device` (path), `interval` (seconds), `auto_start` (true/false). Disabled by default.

### mod_hello — Hello World Example

Minimal example module demonstrating the 4-export interface. Registers `/hello/resources/greeting`. Template for new module development.

### mod_myapp — Example Application

Example application module with counter, events, and ACL demonstration. Shows resources, functions, event emission, and label-based access control patterns.

---

## Federation

Two or more Portal instances can connect and share resources over encrypted, authenticated channels.

### Topology: Hub Routing

A public node acts as hub, relaying between NAT nodes:

```
  ssip888 (NAT) ───TLS───→ hub (public)      ←───TLS─── other-peer (NAT)
                                    │
                     Hub forwards: ssip888 ↔ other-peer
```

NAT nodes connect outbound only. The hub advertises its peers during handshake.
Each node automatically discovers indirect peers and routes through the hub.

### Security

- **TLS encryption** — All federation traffic encrypted with OpenSSL. Self-signed certs auto-generated by `portal -C`.
- **Federation key** — Shared secret authenticated via SHA-256 hash in handshake. Reject unknown peers.
- **ACL across nodes** — User groups/labels travel with every message. Remote node enforces its own ACL.

### Configuration

```ini
# /etc/portal/<instance>/modules/core/mod_node.conf
[mod_node]
node_name        = mynode
listen_port      = 9701
threads_per_peer = 4
tls              = true
cert_file        = /etc/portal/mynode/certs/server.crt
key_file         = /etc/portal/mynode/certs/server.key
tls_verify       = false
federation_key   = shared-secret-here

# /etc/portal/<instance>/portal.conf
[nodes]
peer0 = hub-node=10.0.1.5:9706
```

### Usage

From devtest CLI: `ls` shows `devtest2/` and `asus/` as remote nodes:
```
portal:/> get /devtest2/core/status     ← routed to local peer
portal:/> get /asus/core/status         ← routed to remote NAT peer
portal:/> get /asus/iot/resources/devices ← IoT devices on remote node
```

From HTTP: `curl http://host:8080/api/asus/core/status`

Modules don't know if a path is local or remote — federation is transparent.

---

## Storage

### Three Backends (all active simultaneously)

```
Every user/group change writes to ALL backends:

  1. File    → /etc/portal/devtest/users/admin.conf  (always)
  2. SQLite  → /etc/portal/devtest/portal.db         (if mod_config_sqlite loaded)
  3. PostgreSQL → remote server                       (if mod_config_psql loaded)
```

### File Format (users)

```ini
# /etc/portal/devtest/users/admin.conf
password = $sha256$salt$hexhash
api_key = a1b2c3d4e5f6...
groups = admin,dev
```

### File Format (groups)

```ini
# /etc/portal/devtest/groups/ops.conf
description = Operations team
created_by = admin
```

### SQL Schema (auto-created)

```sql
CREATE TABLE users (username PRIMARY KEY, password, api_key, groups, created_at, updated_at);
CREATE TABLE groups (name PRIMARY KEY, description, created_by, created_at);
CREATE TABLE module_configs (module, key, value, PRIMARY KEY (module, key));
```

---

## Configuration

### Instance Directory

```
/etc/portal/devtest/
├── portal.conf              Main config
├── certs/
│   ├── server.crt           TLS certificate
│   └── server.key           TLS private key
├── users/
│   ├── root.conf            Per-user config
│   └── admin.conf
├── groups/
│   └── ops.conf             Per-group metadata
├── modules/
│   └── web.conf             Per-module config
└── portal.db                SQLite database
```

### Full Configuration Reference

```ini
[core]
modules_dir = /usr/lib/portal/modules   # Where .so files live
socket_path = /var/run/portal.sock      # CLI UNIX socket
pid_file = /var/run/portal.pid          # PID file for daemon mode
data_dir = /etc/portal/devtest          # Users, groups, module configs
tcp_port = 9800                         # Core TCP listener (0=disabled)
udp_port = 9800                         # Core UDP listener (0=disabled)
log_level = info                        # error, warn, info, debug, trace

[modules]
load = cli                              # Modules to load at startup
load = node                             # All modules are optional
load = web
load = config_sqlite
load = config_psql

[mod_node]
node_name = devtest                     # This node's identity
listen_port = 9701                      # Federation listener
threads_per_peer = 4                    # Worker threads per connected node

[mod_web]
bind = 192.168.1.198                    # Bind address (0.0.0.0 = all)
port = 8080                             # HTTP port (0=disabled)
tls_port = 8443                         # HTTPS port (0=disabled)
api_prefix = /api                       # URL prefix for all endpoints
cert_file = /etc/portal/devtest/certs/server.crt
key_file = /etc/portal/devtest/certs/server.key

[mod_config_sqlite]
database = /etc/portal/devtest/portal.db

[mod_config_psql]
host = 192.168.1.87
port = 5433
user = ivoip
password =
database = devportal_conf

[nodes]                                 # Remote nodes to connect to
peer0 = dc-west=10.0.1.5:9701
peer1 = dc-east=10.0.2.5:9701
```

---

## Instance Management

### Create, Start, Delete

```bash
# Create a new instance (auto: ports, certs, users, RULES.md, systemd service)
portal -C myapp

# Start
portal -n myapp -f -d        # foreground with debug
# or
systemctl enable portal-myapp
systemctl start portal-myapp

# Connect CLI
portal -n myapp -r

# Delete (stops service, removes everything)
portal -D myapp
```

Each instance gets its own: config, users, groups, modules, socket, PID file, TCP/UDP ports, TLS certs, storage, RULES.md. Ports auto-detected to avoid conflicts.

### Instance Directory Structure

```
/etc/portal/                             ← Only instance directories (no files)
├── default/                             ← Main instance
├── devtest/                             ← Dev/test instance
└── devtest2/                            ← Federation test peer

/etc/portal/<instance>/                  ← Configuration only
├── portal.conf                          ← Core settings (ports, paths, log level)
├── RULES.md                             ← Laws of God
├── users/                               ← User configs (root.conf, admin.conf)
├── groups/                              ← Group definitions
├── certs/                               ← TLS certs + SSH host key
└── modules/                             ← Per-module config files
    ├── core/                            ← Infrastructure (loaded first)
    │   ├── mod_cli.conf
    │   ├── mod_node.conf
    │   ├── mod_web.conf
    │   ├── mod_ssh.conf
    │   ├── mod_config_sqlite.conf
    │   └── mod_config_psql.conf
    ├── mod_cache.conf                   ← Application modules
    ├── mod_firewall.conf
    ├── mod_xz.conf
    └── ... (42 app module configs)

/var/lib/portal/<instance>/              ← Code + data
├── logic/                               ← Application scripts (Lua, Python, C, Pascal)
├── data/                                ← Runtime data
│   ├── portal.db                        ← SQLite database
│   ├── files/                           ← mod_file sandbox
│   ├── kv/                              ← mod_kv persistent store
│   ├── templates/                       ← mod_template files
│   └── backups/                         ← mod_backup archives
└── modules/                             ← Instance-specific .so modules

/var/log/portal/<instance>/              ← Logs
├── audit.log                            ← mod_audit trail
└── ...
```

Each module has its own `.conf` file with `enabled = true/false`. To disable a module, just set `enabled = false` in its config file — no need to edit `portal.conf`.

### Development Instances

`devtest` and `devtest2` are **reserved for core development only**. They exist to test the Portal core itself, not for applications.

- **devtest** — Primary dev instance (all modules, PostgreSQL + SQLite)
- **devtest2** — Federation peer (connects to devtest for node-to-node testing)

```bash
# After core changes, rebuild and test:
make clean && make && make tests && make install
systemctl restart portal-devtest portal-devtest2
```

Production applications always create their own instances via `portal -C`.

---

## Building a New Application (Step by Step)

### 1. Create the instance

```bash
portal -C myapp
```

This creates `/etc/portal/myapp/` with everything: config, users, certs, systemd service, auto-assigned ports.

### 2. Write your module

Create `mod_myapp.c` anywhere (your workspace, not the core repo):

```c
#include "portal/portal.h"
#include <stdio.h>
#include <string.h>

static portal_module_info_t info = {
    .name = "myapp", .version = "1.0.0",
    .description = "My application", .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

int portal_module_load(portal_core_t *core) {
    core->path_register(core, "/myapp/resources/hello", "myapp");
    core->path_register(core, "/myapp/functions/process", "myapp");
    core->log(core, PORTAL_LOG_INFO, "myapp", "Module loaded");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core) {
    core->path_unregister(core, "/myapp/resources/hello");
    core->path_unregister(core, "/myapp/functions/process");
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp) {
    if (strcmp(msg->path, "/myapp/resources/hello") == 0) {
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, "Hello from MyApp!\n", 18);
        return 0;
    }
    if (strcmp(msg->path, "/myapp/functions/process") == 0) {
        /* Your business logic here */
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, "Processed!\n", 11);
        return 0;
    }
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
```

### 3. Compile

```bash
gcc -shared -fPIC -Wall -Wextra -std=c11 -D_GNU_SOURCE \
    -I/var/www/html/portal/include \
    -I/var/www/html/portal/src \
    -I/var/www/html/portal/lib/libev \
    -o /usr/lib/portal/modules/mod_myapp.so \
    mod_myapp.c /var/www/html/portal/src/core/core_message.c
```

### 4. Add to instance config

Edit `/etc/portal/myapp/portal.conf`:
```ini
[modules]
load = cli
load = node
load = web
load = config_sqlite
load = myapp          # ← add your module
```

### 5. Start

```bash
# Foreground (development)
portal -n myapp -f -d

# Or as a service (production)
systemctl daemon-reload
systemctl enable portal-myapp
systemctl start portal-myapp
```

### 6. Use

```bash
# CLI
portal -n myapp -r
portal:/> ls /myapp
  resources/
  functions/
portal:/> ls /myapp/resources
  hello    [myapp]
portal:/> get /myapp/resources/hello
Hello from MyApp!

# HTTP
curl http://HOST:PORT/api/myapp/resources/hello
curl http://HOST:PORT/api/myapp/functions/process

# Browser
http://HOST:PORT/api/myapp/resources/hello

# Load/unload at runtime (no restart needed)
http://HOST:PORT/api/core/modules/myapp?action=unload
http://HOST:PORT/api/core/modules/myapp?action=load
```

### 7. Connect to other nodes (optional)

Edit `/etc/portal/myapp/portal.conf`:
```ini
[nodes]
peer0 = other-server=10.0.1.5:9700
```

Now your app can access resources on `other-server`:
```bash
portal:/> get /other-server/myapp/resources/hello
```

---

## Creating Modules

Every module is a `.so` shared library exporting 4 functions. See [docs/MODULE_GUIDE.md](docs/MODULE_GUIDE.md) for the complete guide.

### Minimal Example

```c
#include "portal/portal.h"

static portal_module_info_t info = {
    .name = "hello", .version = "1.0.0",
    .description = "Hello module", .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

int portal_module_load(portal_core_t *core) {
    core->path_register(core, "/hello/resources/greeting", "hello");
    core->log(core, PORTAL_LOG_INFO, "hello", "Loaded");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core) {
    core->path_unregister(core, "/hello/resources/greeting");
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp) {
    (void)core; (void)msg;
    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, "Hello from Portal!\n", 19);
    return 0;
}
```

### Build & Load

```bash
gcc -shared -fPIC -Wall -Wextra -Werror -std=c11 -D_GNU_SOURCE \
    -Iinclude -Isrc -Ilib/libev \
    -o modules/mod_hello.so hello.c src/core/core_message.c

# Load at runtime:
portal:/> module load hello
portal:/> get /hello/resources/greeting
Hello from Portal!
```

### Core API Available to Modules

| Function | Description |
|----------|-------------|
| `path_register/unregister` | Register paths this module handles |
| `path_add_label/remove_label` | Set ACL labels on paths |
| `send` | Send message to any path (routed through core) |
| `subscribe/unsubscribe` | Pub/sub event subscriptions |
| `event_register/unregister/emit` | Declare and fire events |
| `storage_register` | Register as a storage provider |
| `module_loaded` | Check if another module is available |
| `fd_add/fd_del` | Register file descriptors with event loop |
| `config_get` | Read module-specific config values |
| `log` | Write log messages (5 levels) |

See [docs/CORE_API.md](docs/CORE_API.md) for full type definitions and function signatures.

---

## Source Code

### Directory Structure

```
portal/
├── include/portal/              6 public API headers
│   ├── portal.h                 Master include
│   ├── types.h                  Messages, responses, labels, auth, trace
│   ├── core.h                   Core API struct (18 function pointers)
│   ├── module.h                 Module interface (4 required exports)
│   ├── storage.h                Storage provider interface
│   └── constants.h              Version, limits, methods, status codes
├── src/
│   ├── main.c                   Entry point, TCP/UDP listeners, remote CLI
│   └── core/                    15 core files + 14 headers
│       ├── core_log.c/h         Colored timestamped logging
│       ├── core_config.c/h      INI parser + per-module sections
│       ├── core_hashtable.c/h   FNV-1a O(1) hash table
│       ├── core_path.c/h        Path registry + label ACL + wildcard
│       ├── core_module.c/h      dlopen loader + refcount + reload
│       ├── core_message.c/h     Message alloc/route/free + labels
│       ├── core_auth.c/h        Users, SHA-256, API keys, sessions
│       ├── core_pubsub.c/h      Pub/sub pattern matching
│       ├── core_events.c/h      Event registry + ACL subscriptions
│       ├── core_wire.c/h        Binary wire protocol
│       ├── core_store.c/h       File-based persistent storage
│       ├── core_storage.c       Multi-provider registry
│       ├── core_event.c/h       libev wrapper + timers + signals
│       ├── core_handlers.c/h    All internal path handlers
│       └── portal_instance.c/h  Instance wiring + crash isolation
├── lib/
│   ├── libev/                   Embedded libev 4.33 (cross-platform)
│   └── sha256/                  Embedded SHA-256 (password hashing)
├── modules/
│   ├── mod_cli/                 UNIX socket CLI (741 lines)
│   ├── mod_node/                TCP federation (586 lines)
│   ├── mod_web/                 HTTP/HTTPS REST API (534 lines)
│   ├── mod_config_sqlite/       SQLite backend (350 lines)
│   ├── mod_config_psql/         PostgreSQL backend
│   ├── mod_cache/               In-memory key-value store with TTL
│   ├── mod_health/              Health checks and uptime
│   ├── mod_cron/                Scheduled task executor
│   ├── mod_json/                JSON response formatter
│   ├── mod_http_client/         HTTP/HTTPS outbound client
│   ├── mod_shm/                 Shared memory regions
│   ├── mod_queue/               FIFO message queues
│   ├── mod_websocket/           WebSocket server
│   ├── mod_mqtt/                MQTT broker
│   ├── mod_email/               SMTP email sender
│   ├── mod_logic/               Logic framework
│   ├── mod_logic_lua/           Lua scripting (Lua 5.4)
│   ├── mod_logic_python/        Python scripting (subprocess)
│   ├── mod_logic_c/             C scripting (gcc compile+load)
│   ├── mod_logic_pascal/        Pascal scripting (fpc compile+load)
│   ├── mod_worker/              Thread pool for background tasks
│   ├── mod_serial/              RS232/serial port communication
│   ├── mod_file/                Sandboxed filesystem operations
│   ├── mod_metrics/             System metrics (CPU, mem, disk, load)
│   ├── mod_audit/               Audit trail logging
│   ├── mod_template/            Template rendering engine
│   ├── mod_proxy/               HTTP reverse proxy
│   ├── mod_dns/                 DNS resolver utility
│   ├── mod_firewall/            Rate limiting + IP filtering
│   ├── mod_gpio/                GPIO pin control (IoT)
│   ├── mod_process/             Sandboxed command execution
│   ├── mod_kv/                  Persistent key-value store
│   ├── mod_webhook/             Webhook dispatcher (HTTP POST)
│   ├── mod_sysinfo/             System information (OS, network)
│   ├── mod_crypto/              Crypto utilities (SHA-256, MD5, Base64)
│   ├── mod_log/                 Log viewer and searcher
│   ├── mod_backup/              Instance backup/restore (tar.gz)
│   ├── mod_ldap/                LDAP/AD authentication
│   ├── mod_xz/                  XZ/LZMA compression (liblzma)
│   ├── mod_gzip/                Gzip compression (zlib)
│   ├── mod_validator/           Input validation (email, IP, URL, JSON)
│   ├── mod_scheduler/           One-shot delayed task scheduler
│   ├── mod_api_gateway/         API gateway with caching + rate limiting
│   ├── mod_acme/                ACME/Let's Encrypt certificate automation
│   ├── mod_admin/               Web admin dashboard (HTML)
│   ├── mod_iot/                 IoT device management (Tapo KLAP, MQTT, GPIO)
│   ├── mod_tunnel/              Port forwarding through federation
│   ├── mod_watchdog/            Hardware watchdog keepalive
│   ├── mod_hello/               Hello world example
│   └── mod_myapp/               Example app (counter, events, ACL)
├── tools/
│   └── portalctl.c              CLI client with raw terminal
├── tests/
│   ├── test_path.c              Path registry (5 tests)
│   ├── test_acl.c               Label ACL (10 tests)
│   ├── test_hashtable.c         Hash table (7 tests)
│   ├── test_pubsub.c            Pub/sub patterns (5 tests)
│   ├── test_wire.c              Wire protocol (3 tests)
│   ├── test_events.c            Event system (7 tests)
│   ├── test_crypto.c            SHA-256, Base64, Hex (10 tests)
│   └── test_validator.c         Email, IP, URL, hostname (10 tests)
├── docs/
│   ├── PHILOSOPHY.md            14 design principles
│   ├── CORE_API.md              Complete API reference (12 sections)
│   └── MODULE_GUIDE.md          Module development guide + checklist
├── etc/
│   ├── devtest.conf             Development instance config
│   ├── devtest2.conf            Second node config
│   ├── portal.service           Default systemd service
│   ├── portal-devtest.service   Devtest systemd service
│   └── portal-devtest2.service  Devtest2 systemd service
├── portal.conf                  Legacy default config (instances use /etc/portal/<name>/)
├── users.conf                   Legacy user file (instances use users/ directory)
├── Makefile                     Build system (51 modules)
└── CLAUDE.md                    Project index
```

All 95 source files have descriptive header comments.

---

## Stats

| Metric | Value |
|--------|-------|
| **Total C source** | ~28,000 lines across 95 source files |
| **Core** | 15 source files, 14 headers (READ-ONLY) |
| **Modules** | 50 (all with R/W/RW access modes + events) |
| **Languages** | 4 (Lua, Python, C, Pascal) |
| **Unit tests** | 57 across 8 test files |
| **Interfaces** | 6 (CLI, HTTP, HTTPS, TCP, UDP, SSH) |
| **Storage backends** | 3 (file + SQLite + PostgreSQL) |
| **Auth methods** | 3 (password, API key, session token + HTTP Basic) |
| **Federation security** | TLS encryption + SHA-256 federation key + hub routing |
| **Access modes** | 66 declarations (READ/WRITE/RW per resource) |
| **Event emissions** | 40+ across all state-modifying modules |
| **External dependencies** | 0 (libev + SHA-256 embedded) |
| **Platforms** | Linux (epoll), macOS (kqueue), Windows (select) |
| **Tested compilers** | gcc 7.5 (Ubuntu 18.04), gcc 12 (Debian 12) |

---

## 14 Laws of God

These rules are absolute and apply to every instance, every module, every contributor:

1. **Document everything** — No undocumented feature exists.
2. **Always write in English** — All code, docs, configs, comments.
3. **Architecture-first** — Order, simplicity, elegant solutions.
4. **Perfect order** — Structure and classification in everything. The most golden rule.
5. **Update docs after testing** — Docs must always reflect current state.
6. **Test everything** — Build, test, verify every feature before release.
7. **Core is READ-ONLY** — New functionality = modules. Core changes only through the engineer.
8. **Resource Properties** — Every resource declares: READ, WRITE, or RW. No resource exists without a declared access mode.
9. **Module Authentication** — Every module authenticates on load (user+password or API key). Default = root. Permissions inherited by all code it executes.
10. **Everything Is an Event** — Every write, execution, or modification emits an event. Events chain: one event triggers N others. Nothing happens silently.
11. **Config Files Are Documentation** — Every .conf file lists ALL options with comments, descriptions, and defaults. The config file IS the docs.
12. **Universal Resource Names** — All resources use the same path syntax everywhere. `ls`, `get`, `set` work identically for local and remote. One syntax, all modules, all paths.
13. **Never Block the Event Loop** — Module operations that do I/O must use thread pool or epoll. Thread pool size configurable. New clients wait when threads busy. The event loop is sacred.
14. **Exclusive Resource Locking** — Physical resources (serial, GPIO, IoT) auto-lock on first write. Implicit keepalive from usage. Auto-release after 60s inactivity. Config protected while locked. Event subscriptions always open.

> The core is the foundation. You don't change the foundation — you build on it.
> Every resource has clear access rights. Every module has clear identity.
> Every change is observable. No resource blocks. Physical access is exclusive.

---

## Further Reading

- [docs/PHILOSOPHY.md](docs/PHILOSOPHY.md) — 14 design principles that govern all development
- [docs/CORE_API.md](docs/CORE_API.md) — Complete type definitions, function signatures, status codes
- [docs/MODULE_GUIDE.md](docs/MODULE_GUIDE.md) — Step-by-step module creation with examples and checklist

## License

TBD
