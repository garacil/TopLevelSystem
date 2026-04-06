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

# Portal Philosophy — Design Rules

These rules govern every decision, every line of code, every module. They are non-negotiable.

---

## 1. Everything Is a Path

Every resource, service, device, API, file, or action is accessed through a path.
A path is the universal address. No exceptions.

```
/node/module/resource
/local/serial/com1/read
/local/web/api/v1/users
/remote-dc1/db/postgres/query
/local/auth/login
```

If it exists, it has a path. If it has a path, it can be reached.

---

## 2. Everything Is a Message

All communication flows through a single structure: the **Message**.
Request, response, event, notification — all are messages.

A message has: a path, a method, headers, a body, and a context.
Nothing communicates outside this structure. No backdoors, no shortcuts.

---

## 3. The Core Does Nothing — Modules Do Everything

The core is a router, a loader, and a referee. It does not implement business logic.
It routes messages, loads modules, enforces access, and traces execution.

All functionality lives in modules. A web server is a module. A database connector is a module.
An RS232 reader is a module. An authentication provider is a module.

The core without modules is silent. That is correct.

---

## 4. No Hard Dependencies — Ever

If module A needs module B and B is not loaded, A does not crash.
A receives a clean "unavailable" response and decides what to do.

Every dependency is soft. Every absence is graceful.
A module must be designed to work degraded, not to demand perfection.

---

## 5. Hot-Load Everything

Modules load, unload, and reload at runtime without stopping the core.
Like Asterisk: `module load mod_web.so`, `module reload mod_db.so`.

The system never stops. Parts come and go. The core endures.

---

## 6. One Interface, Universal

A module that reads RS232 speaks the same language as a module that serves HTTP.
The message structure is the lingua franca. Learn it once, build anything.

This means: a web UI module can query a serial port module using the same
mechanism it uses to query a database module. No adapters, no glue code.

---

## 7. Nodes Are Peers

A node is a running core. Nodes connect to form a network.
A remote path works exactly like a local path — the core handles federation transparently.

```
/local/db/users/query     → handled locally
/node-west/db/users/query → routed to node-west, same message format
```

A module does not need to know if a resource is local or remote.

---

## 8. Security Is a Path Problem

Authentication produces a context. Authorization checks the context against the path.
Every path has access rules. Every message carries identity.

No path is accessible without permission. The default is deny.

---

## 9. Observe Everything

Every message can be traced. Every path can be inspected.
The CLI shows what is happening right now: which messages flow, which modules respond, how long they take.

If you cannot see it, you cannot debug it. If you cannot debug it, you cannot trust it.

---

## 10. Simplicity Is Not Optional

The elegant solution is the correct solution.
If a design requires a paragraph to explain, it is wrong.
If a data structure has fields "just in case," remove them.

One message structure. One routing mechanism. One module interface.
The power comes from composition, not complexity.

---

## 11. C Is the Foundation

The core is written in C (C11/C17). It is minimal, portable, and fast.
Modules are shared libraries (.so on Linux, .dll on Windows).
Any language that can produce a shared library with C ABI can create modules.

The core has no runtime dependencies beyond libc and libdl.

---

## 12. Fail Soft, Log Loud

A module crash does not bring down the core.
A network failure does not freeze the system.
A malformed message is rejected, logged, and forgotten.

Errors are first-class information. They flow through the same message system.
Silent failures are bugs.

---

## 13. No Magic, No Hidden State

Configuration is explicit. Behavior is deterministic.
A module declares what paths it handles, what dependencies it wants, what permissions it needs.

There is no auto-discovery that changes behavior invisibly.
There is no global mutable state outside the core's registries.

---

## 14. Build for Composition

Small modules that do one thing compose into powerful systems.
A web framework is: `mod_http` + `mod_router` + `mod_template` + `mod_static`.
A SCADA system is: `mod_serial` + `mod_modbus` + `mod_db` + `mod_web`.

The same core runs both. The modules are different. The rules are the same.

---

## Summary

| Principle | One-liner |
|-----------|-----------|
| Path | Everything has an address |
| Message | One structure for all communication |
| Core | Routes and loads, nothing more |
| Soft deps | Absence is handled, never fatal |
| Hot-load | Modules come and go at runtime |
| Universal | Same interface for serial ports and REST APIs |
| Nodes | Transparent federation of cores |
| Security | Identity travels with every message |
| Observe | If it moves, you can see it |
| Simplicity | The elegant way or no way |
| C | Minimal, portable, zero-dependency core |
| Fail soft | Crash a module, not the system |
| No magic | Explicit over implicit, always |
| Compose | Small pieces, big systems |
