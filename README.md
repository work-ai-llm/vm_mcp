# vm_mcp

An MCP server that lets an LLM agent inspect and control the local VMware Workstation
GOAD lab: list the lab's VMs, power them on, off and back up, report how much host
capacity is actually left, and determine whether a given guest is genuinely alive or
merely powered on and frozen. The target is the GOAD lab on the author's own
workstation, driven by an agent that can be told things like "bring up the Essos domain
controller and tell me when it's actually answering" without the agent needing to know
anything about `.vmx` paths, `vmrun.exe` argument grammar, or what a half-booted
Windows domain controller looks like from the outside.

## Status

**M3 added: four read-only tools are shipped, the M1 trio plus `guest_health`, the
liveness ladder that tells a powered-on guest from one that is actually
answering. No mutating tool exists.**

Every tool in this repository is read-only. None can change a VM's power state.
The offline suite still runs with no VMware process started; the `guest_health`
live test reads the real instrument when a VM happens to be powered on, and
skips otherwise. The mutating half is deliberately not written yet; the
allowlist that has to gate it is [#15](https://github.com/work-ai-llm/vm_mcp/issues/15).

| Tool | Kind | Shipped |
|---|---|---|
| `list_vms` | read-only | The lab roster and each VM's power state. |
| `vm_status` | read-only | One VM's power state, vCPU, RAM, guest OS, VMware Tools state. |
| `host_resources` | read-only | Measured host CPU, RAM and disk, plus per-VM resident memory and headroom. |
| `guest_health` | read-only | The liveness ladder for one VM: powered on, Tools heartbeating, service port answering. Reports the rung it reached. |
| `start_vm` | mutating | Power on, optionally waiting for the guest to become ready. |
| `stop_vm` | mutating | Power off. Graceful by default; hard-off is opt-in. |
| `restart_vm` | mutating | Stop then start a single VM. |

## Quick start

The server is registered in **`opencode.jsonc` at the repository root** —
project-local and version-controlled. There are two ways to run it.

Remote (what the committed config uses) — start the server yourself, then open
opencode from this directory:

```powershell
..\.venv\Scripts\python.exe -m vm_mcp --transport http
```

Stop it with Ctrl+C; it shuts down cleanly and prints one line. With nothing on
the port, opencode reports `✗ failed` and offers no tools.

stdio (the client spawns the process) and launching from a git worktree are
covered in [`docs/usage.md`](docs/usage.md), along with the transports and the
client config.

## Documentation

The top-level README is the quick start. The reasoning lives in
[`docs/`](docs/README.md):

- [`docs/architecture.md`](docs/architecture.md) — the long-lived decisions:
  why `vmrun`, the two transports, the SDK pin, the registry, the `vmrun` layer,
  the tool-error contract.
- [`docs/tools.md`](docs/tools.md) — how each read-only tool behaves and why.
- [`docs/usage.md`](docs/usage.md) — running the server, the client config,
  worktrees, transports.
- [`docs/security.md`](docs/security.md) — the security posture and the real
  controls.

## Build plan

The full build plan, findings, blockers and milestone breakdown live in
**`PLAN.md`**.

`PLAN.md` and the `research/` directory are **local gitignored working
documents**, not deliverables. They are intentionally untracked: the plan churns
daily and the research directory is scratch material, so neither belongs in the
repository's history. If you are reading this on GitHub and want that context, it
is on the author's machine.

## Repository scope

This repository currently contains the server, its tests, its project-local
opencode config and its documentation. Adding `LICENSE`, CI and contributor
documentation is deliberately deferred — there is nothing to license or build
yet, and inventing a license before the first line of code is committed is a
decision that should be made deliberately rather than by a scaffold.
