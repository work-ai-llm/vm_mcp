# Design

The standing architecture decisions behind the server. The decisions that came
out of specific M1 issues are in [`decisions/`](decisions/); this page holds the
ones that predate them or cut across the whole project.

## It wraps `vmrun.exe`, not pyVmomi and not Vagrant

Every operation the server needs — `list`, `start nogui`, `stop`, `suspend`,
`reset`, `checkToolsState`, `getGuestIPAddress`, `listSnapshots`, guest process
listing — was empirically verified on this machine, with timings. `vmrun` also
addresses a single VM by absolute path, so a bad argument cannot hit the other
five. pyVmomi would add an install and a SOAP credential surface for nothing;
GOAD's own launcher is a thin Vagrant wrapper whose `restart` and `reset`
power-cycle the *entire* lab, and `vagrant global-status` was observed reporting
all six VMs as running while none were.

How the invocation is constructed is [ADR 0003](decisions/0003-vmrun-invocation.md).

## Two transports over one tool surface, loopback-only by default

stdio is the default because it opens no port: the client spawns the process and
owns its lifetime, so a server that can power off a domain controller is not
sitting on a socket waiting for anything. `--transport http` exists for a
different reason: a client that should not control the server's lifetime, and a
second machine that needs to reach the same server. The server binds `127.0.0.1`
by default. Widening the bind address to `0.0.0.0` is a deliberate flag and is
not reachable by accident, because the whole threat this project is aimed at is a
prompt-injected agent deciding to power off a DC. Both transports expose an
identical tool surface, so nothing in a tool definition knows or cares which one
carried the call.

## The MCP Python SDK is pinned to v2 (`mcp==2.2.0`)

v2 is a breaking rewrite in which `FastMCP` was removed; the API is
`from mcp.server import MCPServer` with `@mcp.tool()`. The pin is exact, not
`>=`, because an unpinned dependency resolves to a future major and breaks on
import. (An existing local project, `kali_mcp`, is already broken by exactly
this: it imports the removed `mcp.server.fastmcp` and pins no upper bound.) The
SDK also no longer reads `.env` files.

## Callers never supply paths; names resolve through the live VMware registry

Exactly one function (`roster.resolve`) maps a caller-supplied identifier to a
VM, and it only ever returns a path that the registry itself lists. A tool
accepting a caller-supplied path would be an arbitrary-file-primitive with a
power switch on it. The registry is `%APPDATA%\VMware\inventory.vmls` — the same
file the GUI reads to build its library — so the roster is discovered rather than
pinned in the repository. Paths are still never globbed: a glob would happily
accept a path outside the lab.

Full rationale and the rejected alternatives are in
[ADR 0002](decisions/0002-roster-and-list_vms.md).

## Module layout

| Module | Responsibility |
|---|---|
| `src/vm_mcp/server.py` | The three tools, the CLI, both transports. |
| `src/vm_mcp/roster.py` | Reads `inventory.vmls`; resolves a name/uuid to a VM. |
| `src/vm_mcp/vmrun.py` | The only place `vmrun.exe` is executed. |
| `src/vm_mcp/hostinfo.py` | Host CPU/RAM/disk via psutil; per-VM RSS. |
| `src/vm_mcp/__main__.py` | Entry point so `python -m vm_mcp` works. |
| `vm_mcp.py` (repo root) | Launcher for worktrees; see [`usage.md`](usage.md). |

`server.py` is deliberately not named `vm_mcp.py`: a module named after the
package it lives in shadows it, so running it puts its own directory on
`sys.path` and `from vm_mcp import roster` resolves to the file instead of the
package. The root `vm_mcp.py` takes that hit on purpose and inserts `src` ahead
of itself to compensate.
