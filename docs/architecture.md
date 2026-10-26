# Architecture

The long-lived decisions behind vm_mcp, in one place. Decisions that came out of
a specific issue are tagged with its number; the rest are the standing choices
the project was built on. Per-tool behaviour lives in
[`tools.md`](tools.md).

## It wraps `vmrun.exe`, not pyVmomi and not Vagrant

Every operation the server needs — `list`, `start nogui`, `stop`, `suspend`,
`reset`, `checkToolsState`, `getGuestIPAddress`, `listSnapshots`, guest process
listing — was empirically verified on this machine, with timings. `vmrun` also
addresses a single VM by absolute path, so a bad argument cannot hit the other
five. pyVmomi would add an install and a SOAP credential surface for nothing;
GOAD's own launcher is a thin Vagrant wrapper whose `restart` and `reset`
power-cycle the *entire* lab, and `vagrant global-status` was observed reporting
all six VMs as running while none were.

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

## Callers never supply paths; names resolve through the live registry (#7)

Exactly one function (`roster.resolve`) maps a caller-supplied identifier to a
VM, and it only ever returns a path that the registry itself lists. A tool
accepting a caller-supplied path would be an arbitrary-file-primitive with a
power switch on it. Paths are never globbed either: a glob would happily accept
a path outside the lab.

### The roster is the VMware registry

`vmrun list` reports only the **running** set — with the lab powered down it
returns an empty list, not an error — so on its own it cannot tell "the VM is
off" from "the VM does not exist". Two other candidates were rejected: a
filesystem glob for `*.vmx` (finds VMs deleted years ago, carries no identity or
power state) and a hardcoded allowlist (wrong for a shared server; it reports
"unknown VM" for every VM the caller actually owns).

The roster is therefore `%APPDATA%\VMware\inventory.vmls` — the same file the
GUI reads to build its library — parsed read-only by `roster.py`:

- INI-style `key = "value"`, not JSON despite the `.vmls` name. Its first line is
  `.encoding = "windows-1251"`, so decoding is driven by that directive.
- Identity is `vmlist<N>.config` (absolute `.vmx` path), `.DisplayName` and
  `.UUID`; blocks with an empty config are stubs and are skipped.
- The free-text `guest` and `notes` fields are **not read** — user-typed, they
  rot, and they were verified wrong on 3 of the 8 VMs on this host. Guest OS
  comes from the `.vmx`.
- It is re-read on **every call**, never cached: ~7 KB, well under a millisecond,
  and caching created an order-dependent way for `list_vms` and `vm_status` to
  disagree about which VMs exist.

### Out-of-lab VMs are not excluded

The registry is everything registered with VMware on the host, not just the lab,
so `list_vms` reports **all** registered VMs. The tool's promise is "every VM
registered with VMware Workstation", not "the lab": a lab filter would need a lab
definition the server does not have, and any definition baked in would lie the
moment it runs elsewhere. Lab membership stays the caller's concern.

### A missing `.vmx` is reported, not hidden

A registry entry can outlive its `.vmx`. This is reported rather than omitted or
treated as fatal: `vm_status` sets `vmx_exists: false`, and `list_vms` still
lists the entry. Because it is not running, its `power_state` reads `stopped`, and
`vmx_exists` is what separates "gone" from "off".

### Names: report the registry's spelling, accept the common ones

Output uses the registry's display name (`provider: GOAD-DC01`). Resolution
accepts loose aliases so a caller is not forced to reproduce the `provider: `
prefix: the prefix-stripped name and the `.vmx` filename stem both match,
case-insensitively. An ambiguous match is an error listing the candidates, never
a guess. UUID is the only unambiguous key — it equals the `.vmx` `uuid.bios` and
survives a rename — and a UUID that matches nothing is an error, never a fallback
to name matching. The registry-backed resolution is the security boundary every
mutating tool sits behind (see [`security.md`](security.md)).

## How the server invokes `vmrun` (#8)

One module, `vmrun.py`, is the only place `vmrun.exe` is executed. It exposes
`run_vmrun()` (the primitive), `list_running_vmx()` and `tools_state()`; every
tool calls it, none builds its own command line. The four sub-decisions:

- **Binary location:** a pinned absolute path (`VMRUN_PATH`), overridable per
  call for tests. A **missing binary fails the call**, not startup
  (`VmrunUnavailable`), so import-time work stays off the handshake's critical
  path.
- **Concurrency:** unconstrained — no lock. A global lock would let one stuck
  call block every tool, which is exactly what the timeout prevents.
- **Timeouts:** per-command ceilings (20s default, 15s for `list`). A **timeout is
  distinguishable from a non-zero exit** — a raise vs `VmrunResult(ok=False)` —
  and neither is ever returned as an empty success.
- **Argument vector, not a shell:** `create_subprocess_exec`, so a VM named
  `a & b` is one argument, not an injection. The command is
  `[<vmrun>, "-T", "ws", *args]`; `-T ws` pins the local Workstation instance.

`vmrun` writes its own errors to **stdout** (not stderr) with exit `-1`, and this
host runs a cp866 console, so both streams are captured, decoded as UTF-8 with
replacement, and merged.

## The tool-error contract (#3)

`mcp.Client` defaults to `raise_exceptions=False`: an unknown tool or bad
arguments come back as a `CallToolResult` with `is_error=True`, not a Python
exception. (The claim in `PLAN.md` §4 that errors are always raised was wrong and
had never been verified.) The contract:

- **Tests assert at both layers, deliberately.** Protocol tests assert on
  `is_error` (what the model sees); function tests assert `pytest.raises(ToolError)`
  (the handler raises before the SDK converts it).
- **Handlers `raise ToolError`, never return error-shaped dicts.**
- **Validation errors pass through raw**; summarising them is deferred to M4.
- **Clients stay on `raise_exceptions=False`.**

Failure and degradation are different things: a tool that cannot reach VMware
returns a *degraded value* (`power_state: unknown`, `observed_via: unavailable`),
not `is_error=True`. Only caller-facing mistakes (an identifier that does not
resolve) are errors.

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
