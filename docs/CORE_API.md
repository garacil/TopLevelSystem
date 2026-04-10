# Portal Core API Reference

Complete reference for all interfaces, types, and conventions used by Portal modules.

Include one header to get everything:

```c
#include "portal/portal.h"
```

---

## 1. Types

### portal_header_t — Key-Value Pair

```c
typedef struct {
    char *key;
    char *value;
} portal_header_t;
```

Used in messages and responses for metadata. Examples: `action=load`, `prefix=/core`, `token=abc123`.

### portal_labels_t — Label Set

```c
typedef struct {
    char    labels[PORTAL_MAX_LABELS][PORTAL_MAX_LABEL_LEN];
    int     count;
} portal_labels_t;
```

Used for both user permissions and path access control. Labels are simple strings like `"admin"`, `"dev"`, `"finance"`.

**Functions:**

| Function | Returns | Description |
|----------|---------|-------------|
| `portal_labels_add(ls, label)` | `int` | Add a label. Idempotent. Returns 0 on success. |
| `portal_labels_remove(ls, label)` | `int` | Remove a label. Returns -1 if not found. |
| `portal_labels_has(ls, label)` | `int` | Returns 1 if label exists, 0 otherwise. |
| `portal_labels_intersects(a, b)` | `int` | Returns 1 if sets share at least one label. |
| `portal_labels_clear(ls)` | `void` | Remove all labels. |

### portal_auth_t — Authentication Context

```c
typedef struct {
    char            *user;       /* username */
    char            *token;      /* session token */
    portal_labels_t  labels;     /* user's access labels */
} portal_auth_t;
```

### portal_trace_t — Trace Context

```c
typedef struct {
    uint64_t  trace_id;       /* unique trace identifier */
    uint64_t  parent_id;      /* parent message id (for chains) */
    uint64_t  timestamp_us;   /* microsecond timestamp */
    uint16_t  hops;           /* number of nodes traversed */
} portal_trace_t;
```

### portal_ctx_t — Message Context

Travels with every message. Carries identity, tracing, and origin.

```c
typedef struct {
    portal_auth_t   auth;            /* who is sending */
    portal_trace_t  trace;           /* debugging/tracing */
    char           *source_node;     /* originating node */
    char           *source_module;   /* originating module */
} portal_ctx_t;
```

### portal_msg_t — The Universal Message

Every interaction in Portal is a message. Requests, commands, events, queries — all messages.

```c
typedef struct {
    uint64_t          id;             /* unique message id (auto-assigned) */
    char             *path;           /* destination: "/module/resource" */
    uint8_t           method;         /* what to do (GET, SET, CALL, etc.) */
    uint16_t          header_count;   /* number of headers */
    portal_header_t  *headers;        /* key-value metadata */
    void             *body;           /* payload (any format) */
    size_t            body_len;       /* payload length */
    portal_ctx_t     *ctx;            /* auth + trace + source */
} portal_msg_t;
```

**Message Builder Functions:**

| Function | Description |
|----------|-------------|
| `portal_msg_alloc()` | Create a new message (auto-assigns id). Caller must free. |
| `portal_msg_free(msg)` | Free message and all its contents. |
| `portal_msg_set_path(msg, path)` | Set destination path (copies string). |
| `portal_msg_set_method(msg, method)` | Set method (GET, SET, CALL, etc.). |
| `portal_msg_set_body(msg, data, len)` | Set body payload (copies data). |
| `portal_msg_add_header(msg, key, val)` | Add a key-value header (copies strings). |

### portal_resp_t — Response

Returned by the handler that processes a message.

```c
typedef struct {
    uint16_t          status;         /* status code (200, 404, etc.) */
    uint16_t          header_count;   /* number of response headers */
    portal_header_t  *headers;        /* response metadata */
    void             *body;           /* response payload */
    size_t            body_len;       /* payload length */
} portal_resp_t;
```

**Response Builder Functions:**

| Function | Description |
|----------|-------------|
| `portal_resp_alloc()` | Create a new response. Caller must free. |
| `portal_resp_free(resp)` | Free response and all its contents. |
| `portal_resp_set_status(resp, code)` | Set status code. |
| `portal_resp_set_body(resp, data, len)` | Set body payload (copies data). |

---

## 2. Methods

Methods define the intent of a message. Use the appropriate method for clarity.

| Constant | Value | When to use |
|----------|-------|-------------|
| `PORTAL_METHOD_GET` | 0x01 | Read a resource. No side effects. |
| `PORTAL_METHOD_SET` | 0x02 | Create or update a resource. |
| `PORTAL_METHOD_CALL` | 0x03 | Execute an action (login, reboot, compile). |
| `PORTAL_METHOD_EVENT` | 0x04 | Emit a notification (fire and forget). |
| `PORTAL_METHOD_SUB` | 0x05 | Subscribe to events on a path pattern. |
| `PORTAL_METHOD_UNSUB` | 0x06 | Unsubscribe from events. |
| `PORTAL_METHOD_META` | 0x07 | Query metadata about a path (labels, module, etc.). |

---

## 3. Status Codes

Every response carries a status code. Use consistently across all modules.

| Code | Constant | Meaning |
|------|----------|---------|
| 200 | `PORTAL_OK` | Success |
| 201 | `PORTAL_CREATED` | Resource created |
| 202 | `PORTAL_ACCEPTED` | Accepted for processing |
| 400 | `PORTAL_BAD_REQUEST` | Invalid message (missing fields, bad format) |
| 401 | `PORTAL_UNAUTHORIZED` | Authentication required or failed |
| 403 | `PORTAL_FORBIDDEN` | Authenticated but no access (label mismatch) |
| 404 | `PORTAL_NOT_FOUND` | Path not registered |
| 409 | `PORTAL_CONFLICT` | Resource conflict (already exists, locked) |
| 500 | `PORTAL_INTERNAL_ERROR` | Module internal error |
| 503 | `PORTAL_UNAVAILABLE` | Module not loaded (soft dependency down) |

---

## 4. Core API (portal_core_t)

Every module receives a `portal_core_t *core` pointer. This is the module's only interface to the system. Never access internal state directly.

### Path Management

```c
/* Register a path this module handles */
int  core->path_register(core, "/mymod/resource", "mymod");

/* Set access mode (Law 8: R/W/RW) */
int  core->path_set_access(core, "/mymod/resource", PORTAL_ACCESS_READ);
/* PORTAL_ACCESS_READ (0x01), PORTAL_ACCESS_WRITE (0x02), PORTAL_ACCESS_RW (0x03) */

/* Unregister a path (call in unload) */
int  core->path_unregister(core, "/mymod/resource");

/* Restrict a path with a label */
int  core->path_add_label(core, "/mymod/secret", "admin");

/* Remove a label restriction */
int  core->path_remove_label(core, "/mymod/secret", "admin");
```

**Law 8 compliance:** Every `path_register` must be followed by `path_set_access`. Resources use `PORTAL_ACCESS_READ`, functions use `PORTAL_ACCESS_RW`.

**Rules:**
- Register paths in `portal_module_load()`, unregister in `portal_module_unload()`.
- A path can only be registered by one module at a time.
- Path format: `/<module>/<resource>[/<sub>]`. Always starts with `/`.

### Message Routing

```c
/* Send a message to any path in the system */
int  core->send(core, msg, resp);
```

This is how modules communicate. The core:
1. Looks up the path in the hash table (O(1))
2. Checks label-based access control
3. Routes to the target module's `portal_module_handle()`
4. Returns the response

**Return:** 0 on success, -1 on error (check `resp->status`).

### Soft Dependencies

```c
/* Check if another module is loaded before using it */
int  core->module_loaded(core, "db");
```

Returns 1 if loaded, 0 if not. Always check before sending to a dependency.

### Observability (read-only enumeration)

```c
/* Walk all loaded modules with their msg counters */
int  core->module_iter(core, my_module_cb, userdata);

/* Walk all registered paths with their owning module */
int  core->path_iter(core, my_path_cb, userdata);
```

**Callback signatures:**
```c
void my_module_cb(const char *name, const char *version, int loaded,
                  uint64_t msg_count, uint64_t last_msg_us, void *ud);

void my_path_cb(const char *path, const char *module_name, void *ud);
```

`msg_count` is incremented on every dispatch into the module (single-threaded, no locks). `last_msg_us` is a monotonic microsecond timestamp of the last call. Use these for observability views like the CLI `top` builtin (implemented in `mod_process` → `/process/resources/portal_top`). These iterators are read-only — they cannot mutate core state.

### Event Loop (I/O)

```c
/* Register a file descriptor for async I/O */
int  core->fd_add(core, fd, EV_READ, my_callback, my_data);

/* Remove a file descriptor */
int  core->fd_del(core, fd);
```

**Callback signature:**
```c
void my_callback(int fd, uint32_t events, void *userdata);
```

**Events:** `EV_READ`, `EV_WRITE`, `EV_ERROR` (from embedded libev).

**Rules:**
- Never create your own threads or polling loops.
- Register fds with the core event loop.
- Works cross-platform (epoll on Linux, kqueue on macOS, select on Windows).

### Pub/Sub (Events)

```c
/* Subscribe to events on a path pattern */
int  core->subscribe(core, "/mymod/events", handler_fn, userdata);

/* Unsubscribe */
int  core->unsubscribe(core, "/mymod/events", handler_fn);
```

**Handler signature:**
```c
void handler_fn(const portal_msg_t *msg, void *userdata);
```

### Event System

Modules can register events, emit them, and subscribe to events from other modules:

```c
/* Register an event your module will emit */
portal_labels_t labels = {0};
portal_labels_add(&labels, "dev");
core->event_register(core, "/events/mymod/data_ready",
                     "New data available", &labels);

/* Emit an event (fans out to all subscribers with matching ACL) */
core->event_emit(core, "/events/mymod/data_ready", "payload", 7);

/* Unregister on unload */
core->event_unregister(core, "/events/mymod/data_ready");
```

Events are ACL-controlled: subscribers must have labels matching the event's labels. The `root` label always has access.

### Configuration

Modules read config from multiple sources (checked in order):

1. **Database** (SQLite/PostgreSQL) — authoritative, survives restarts
2. **Per-module .conf files** (`modules/mod_mymod.conf` or `modules/core/mod_mymod.conf`)
3. **portal.conf** sections

```c
/* Reads from DB first, then .conf files. Section: [mod_mymod] */
const char *port = core->config_get(core, "mymod", "port");
```

Config values can be changed at runtime via `/core/config/set` (CLI: `config set mymod port 9090`).

### Logging

```c
core->log(core, PORTAL_LOG_INFO, "mymod", "Started with %d items", count);
```

**Levels:** `PORTAL_LOG_ERROR`, `PORTAL_LOG_WARN`, `PORTAL_LOG_INFO`, `PORTAL_LOG_DEBUG`, `PORTAL_LOG_TRACE`.

**Rules:**
- Always use `core->log()`. Never write to stdout/stderr.
- Use the module name as the second parameter for filtering.
- ERROR: something broke. WARN: something unexpected. INFO: lifecycle events. DEBUG: internal state. TRACE: message flow.

---

## 5. Module Interface

Every module is a shared library (`.so` on Linux, `.dll` on Windows) that exports exactly 4 symbols.

### File Naming

```
mod_<name>.so
```

Examples: `mod_cli.so`, `mod_db.so`, `mod_web.so`, `mod_serial.so`.

### Required Exports

#### 1. portal_module_info

```c
portal_module_info_t *portal_module_info(void);
```

Returns a static descriptor. Called once when the module is loaded.

```c
typedef struct {
    const char  *name;        /* short name: "cli", "db", "web" */
    const char  *version;     /* semver: "1.0.0" */
    const char  *description; /* human-readable: "Database connector" */
    const char **soft_deps;   /* NULL-terminated: {"auth", "log", NULL} or NULL */
} portal_module_info_t;
```

#### 2. portal_module_load

```c
int portal_module_load(portal_core_t *core);
```

Called when the module is loaded. This is where you:
- Register paths
- Set labels on paths
- Open sockets/files
- Register file descriptors with the event loop
- Allocate resources

**Return:** `PORTAL_MODULE_OK` (0) on success, `PORTAL_MODULE_FAIL` (-1) on failure.

#### 3. portal_module_unload

```c
int portal_module_unload(portal_core_t *core);
```

Called when the module is unloaded. This is where you:
- Unregister all paths
- Remove all fds from the event loop
- Close all sockets/files
- Free all allocated memory

**Return:** `PORTAL_MODULE_OK` (0).

#### 4. portal_module_handle

```c
int portal_module_handle(portal_core_t *core,
                         const portal_msg_t *msg,
                         portal_resp_t *resp);
```

Called when a message arrives at one of your registered paths. You must:
- Check `msg->path` to know which resource is being addressed
- Check `msg->method` to know what action is requested
- Read `msg->headers` and `msg->body` for input data
- Set `resp->status` and optionally `resp->body` for the response

**Return:** 0 on success, -1 on error.

---

## 6. Access Control (Labels)

Portal uses label-based access control. Simple, flexible, no role hierarchies.

### How It Works

1. **Users have labels:** `admin`, `dev`, `finance`, `viewer`
2. **Paths have labels:** set by modules via `core->path_add_label()`
3. **Access check:** if `intersection(user.labels, path.labels) != empty` → **ALLOW**

### Rules

| Path Labels | User Labels | Result |
|-------------|-------------|--------|
| (none) | (any) | **ALLOW** — open path |
| `admin` | `admin, dev` | **ALLOW** — "admin" matches |
| `admin` | `dev, viewer` | **DENY** — no match |
| `admin, dev` | `dev` | **ALLOW** — "dev" matches |
| (any) | (root user) | **ALLOW** — root bypasses all |

### Module Example

```c
int portal_module_load(portal_core_t *core)
{
    /* Public path — anyone can access */
    core->path_register(core, "/mymod/public", "mymod");

    /* Restricted path — only admin and dev */
    core->path_register(core, "/mymod/admin", "mymod");
    core->path_add_label(core, "/mymod/admin", "admin");
    core->path_add_label(core, "/mymod/admin", "dev");

    return PORTAL_MODULE_OK;
}
```

The core enforces access automatically on every `send()`. Your module does not need to check permissions — it only receives messages that have already passed the ACL.

---

## 7. Internal Core Paths

These paths are registered by the core at startup. Available to all modules.

### Core Management

| Path | Method | Headers | Description |
|------|--------|---------|-------------|
| `/core/status` | GET | — | Portal version, module count, path count |
| `/core/modules` | GET | — | List all loaded modules |
| `/core/modules/<name>` | CALL | `action=load\|unload\|reload` | Module lifecycle |
| `/core/paths` | GET | — | List all registered paths |
| `/core/ls` | GET | `prefix=/foo` | List next-level children at prefix |
| `/core/resolve` | GET | `cwd=/a/b`, `target=../c` | Resolve relative path |

### Authentication

| Path | Method | Headers | Description |
|------|--------|---------|-------------|
| `/auth/login` | CALL | `username=x`, `password=y` or `api_key=k` | Login (password or API key) |
| `/auth/logout` | CALL | `token=x` | End session |
| `/auth/whoami` | GET | `token=x` | Current user + labels |
| `/auth/key` | GET | `token=x` | Show user's API key |
| `/auth/key/rotate` | CALL | `token=x` | Generate new API key |

### User Management

| Path | Method | Headers | Description |
|------|--------|---------|-------------|
| `/users` | GET | — | List all users + groups |
| `/users/<name>` | GET | — | User info (groups, key status) |
| `/users/<name>` | SET | `password=x`, `groups=a,b` | Create user |
| `/users/<name>/password` | CALL | `password=newpass` | Change password |

### Group Management

| Path | Method | Headers | Description |
|------|--------|---------|-------------|
| `/groups` | GET | — | List all groups + member counts |
| `/groups/<name>` | GET | — | Group info + members |
| `/groups/<name>` | SET | `description=text` | Create group |
| `/groups/<name>/add` | CALL | `user=username` | Add user to group |
| `/groups/<name>/remove` | CALL | `user=username` | Remove user from group |

### Event System

| Path | Method | Headers | Description |
|------|--------|---------|-------------|
| `/events` | GET | — | List all registered events |
| `/events/<path>` | SUB | `notify_fd=N` | Subscribe to event |
| `/events/<path>` | UNSUB | — | Unsubscribe |

### Module-Specific Paths (when loaded)

| Path | Module | Description |
|------|--------|-------------|
| `/node/status` | mod_node | Node name, port, peer count |
| `/node/resources/status` | mod_node | Node name, port, peer count |
| `/node/resources/peers` | mod_node | Connected peer list + status |
| `/web/resources/status` | mod_web | HTTP/HTTPS port, prefix, status |
| `/core/storage` | core | Active storage backends |
| `/core/storage/<name>/resources/status` | core | Provider connection details |
| `/core/storage/<name>/functions/sync` | core | Force sync to provider |

### Using Core Paths from a Module

```c
/* Example: check system status from your module */
portal_msg_t *msg = portal_msg_alloc();
portal_resp_t *resp = portal_resp_alloc();

portal_msg_set_path(msg, "/core/status");
portal_msg_set_method(msg, PORTAL_METHOD_GET);

core->send(core, msg, resp);

if (resp->status == PORTAL_OK && resp->body) {
    /* resp->body contains the status text */
}

portal_msg_free(msg);
portal_resp_free(resp);
```

---

## 8. HTTP REST API (mod_web)

When `mod_web` is loaded, every Portal path becomes an HTTP endpoint under the configured prefix (default `/api`):

```
GET  /api/core/status        → portal GET /core/status
POST /api/users/bob?pass=x   → portal SET /users/bob (header: pass=x)
PUT  /api/groups/ops/add?user=bob → portal CALL /groups/ops/add
```

### Authentication

```bash
# With API key (query parameter)
curl "http://host:8080/api/users?api_key=YOUR_KEY"

# With Bearer token (header)
curl -H "Authorization: Bearer YOUR_TOKEN" http://host:8080/api/users
```

### CORS

mod_web includes CORS headers (`Access-Control-Allow-Origin: *`) for browser access. OPTIONS preflight requests are handled automatically.

### HTTPS

Configure TLS with certificate and key files:

```ini
[mod_web]
port = 8080
tls_port = 8443
cert_file = /etc/portal/devtest/certs/server.crt
key_file = /etc/portal/devtest/certs/server.key
```

Generate self-signed certs for development:
```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
    -days 3650 -nodes -subj "/CN=portal/O=Portal"
```

## 9. Communication Patterns

### Request / Response (synchronous)

The default pattern. Send a message, get a response.

```c
portal_msg_t *msg = portal_msg_alloc();
portal_resp_t *resp = portal_resp_alloc();

portal_msg_set_path(msg, "/db/users");
portal_msg_set_method(msg, PORTAL_METHOD_GET);
portal_msg_add_header(msg, "id", "42");

core->send(core, msg, resp);

if (resp->status == PORTAL_OK) {
    /* process resp->body */
}

portal_msg_free(msg);
portal_resp_free(resp);
```

### Fire and Forget (events)

Use `PORTAL_METHOD_EVENT` for notifications that don't need a response.

```c
portal_msg_t *msg = portal_msg_alloc();
portal_resp_t *resp = portal_resp_alloc();

portal_msg_set_path(msg, "/log/event");
portal_msg_set_method(msg, PORTAL_METHOD_EVENT);
portal_msg_set_body(msg, "user_login:admin", 16);

core->send(core, msg, resp);
/* resp->status checked but not critical */

portal_msg_free(msg);
portal_resp_free(resp);
```

### Module-to-Module Communication

Modules never call each other directly. All communication goes through the core via paths.

```
Module A → core->send("/modB/resource") → Core Router → Module B
         ← resp                          ← ACL Check  ←
```

This means:
- Module A doesn't need to know Module B's implementation
- The core handles access control transparently
- If Module B is unloaded, Module A gets `503 UNAVAILABLE`
- If Module B is on a remote node, the path still works (via mod_node)

---

## 10. Constants Reference

### Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `PORTAL_MAX_PATH_LEN` | 1024 | Maximum path string length |
| `PORTAL_MAX_MODULE_NAME` | 64 | Maximum module name length |
| `PORTAL_MAX_MODULES` | 256 | Maximum loaded modules |
| `PORTAL_MAX_HEADERS` | 32 | Maximum headers per message |
| `PORTAL_MAX_EVENTS` | 64 | Maximum concurrent epoll events |
| `PORTAL_MAX_LABELS` | 32 | Maximum labels per set |
| `PORTAL_MAX_LABEL_LEN` | 64 | Maximum label string length |

### Federation Limits (mod_node)

| Constant | Value | Description |
|----------|-------|-------------|
| `NODE_MAX_PEERS` | 2048 | Maximum concurrent federation peers |
| `NODE_MAX_FDS` | 8192 | Maximum fd→SSL lookup table size |
| `NODE_MAX_THREADS` | 16 | Maximum worker connections per peer |
| `NODE_PEER_MAX_PATHS` | 32 | Maximum path registrations per remote peer |
| `NODE_PEER_PATH_LEN` | 256 | Maximum path string length per peer |

Memory per peer: ~10 KB (with paths[32][256]). At 2048 peers: ~20 MB.

### Special Values

| Constant | Value | Description |
|----------|-------|-------------|
| `PORTAL_ROOT_USER` | `"root"` | Username that bypasses all ACL |
| `PORTAL_MODULE_OK` | 0 | Module lifecycle success |
| `PORTAL_MODULE_FAIL` | -1 | Module lifecycle failure |

---

## 11. Building a Module

### Compile

```bash
gcc -shared -fPIC -Wall -Wextra -Werror \
    -std=c11 -D_GNU_SOURCE \
    -Iinclude -Isrc -Ilib/libev \
    -o modules/mod_mymod.so \
    modules/mod_mymod/mod_mymod.c \
    src/core/core_message.c
```

### Install

Place `mod_mymod.so` in the modules directory (configured in `portal.conf`).

### Load at Runtime

```
portal> module load mymod
```

Or add to `portal.conf`:

```ini
[modules]
load = cli
load = mymod
```

### Test

```
portal> ls /mymod
portal> module list
```

---

## 12. Module Rules

1. **Export exactly 4 symbols.** No more, no less.
2. **Register all paths in `load()`.** Unregister all in `unload()`.
3. **No hard dependencies.** Check `module_loaded()` before using other modules. If missing, degrade gracefully — return `503` or skip functionality.
4. **Clean up on unload.** Free memory, close fds, unregister paths. Leave no trace.
5. **Use the event loop.** Register fds with `fd_add()`. Never create threads, never poll, never block.
6. **Log through the core.** Use `core->log()`. Never `printf`, never `fprintf(stderr, ...)`.
7. **Set response status.** Every `portal_module_handle()` must set `resp->status`.
8. **Paths start with `/module_name/`.** Convention for namespace isolation.
9. **Use labels for access control.** Restrict sensitive paths with `path_add_label()`.
10. **Body format is your choice.** Text, JSON, binary, protobuf — whatever fits. Document it.
