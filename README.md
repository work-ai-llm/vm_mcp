# vm_mcp

An MCP server that lets an LLM agent inspect and control the local VMware Workstation
GOAD lab: list the lab's VMs, power them on, off and back up, report how much host
capacity is actually left, and determine whether a given guest is genuinely alive or
merely powered on and frozen. The target is the six-machine AD lab on the author's own
workstation, driven by an agent that can be told things like "bring up the Essos domain
controller and tell me when it's actually answering" without the agent needing to know
anything about `.vmx` paths, `vmrun.exe` argument grammar, or what a half-booted
Windows domain controller looks like from the outside.

## Status

**Research and planning only. Nothing is implemented.** There is no server, no
`pyproject.toml`, no source tree and no installed package in this repository. The
tracked content is a `.gitignore` and this README. No MCP tools exist yet, and no
claim in this README should be read as describing working software.

What *does* exist is the research that the design is based on: every control operation
this server intends to wrap was executed against the real lab and its behaviour and
timings recorded. That research is deliberately untracked and lives in `PLAN.md` and
`research/`. The first code milestone is the SDK handshake — the current MCP Python SDK
is a breaking rewrite, so "does a trivial tool round-trip at all" is not yet a
guaranteed yes.

## Planned tool surface

| Tool | Kind | Purpose |
|---|---|---|
| `list_vms` | read-only | The lab roster and each VM's power state. |
| `vm_status` | read-only | Per-VM power state, configured vCPU/RAM, snapshots. |
| `host_resources` | read-only | Measured host CPU, RAM and disk, plus per-VM RAM headroom. |
| `guest_health` | read-only | Liveness ladder. Distinguishes `up` / `degraded` / `down` / `unknown` and reports how far up the ladder it got. |
| `start_vm` | mutating | Power on, optionally waiting for the guest to become ready. |
| `stop_vm` | mutating | Power off. Graceful by default; hard-off is opt-in. |
| `restart_vm` | mutating | Stop then start a single VM. |

The mutating tools are intended to ship disabled by default in client configuration,
gated behind an explicit per-agent opt-in. `guest_health` is the reason the project
exists: it must separate "powered on" from "actually responsive", so a VM that is up
but wedged reports as `degraded`, not `up`.

## Design decisions

1. **It wraps `vmrun.exe`, not pyVmomi and not Vagrant.** Every operation the server
   needs — `list`, `start nogui`, `stop`, `suspend`, `reset`, `checkToolsState`,
   `getGuestIPAddress`, `listSnapshots`, guest process listing — was empirically
   verified on this machine, with timings. `vmrun` also addresses a single VM by
   absolute path, so a bad argument cannot hit the other five. pyVmomi would add an
   install and a SOAP credential surface for nothing; GOAD's own launcher is a thin
   Vagrant wrapper whose `restart` and `reset` power-cycle the *entire* lab, and
   `vagrant global-status` was observed reporting all six VMs as running while none
   were.

2. **stdio transport only — no port, no listener, no auth surface.** The whole point of
   this server is that it can power off a domain controller. It should therefore not be
   listening on a socket for anything to connect to. Remote/HTTP transport is out of
   scope by design, not by omission.

3. **The MCP Python SDK is pinned to v2 (`mcp==2.2.0`).** v2 is a breaking rewrite in
   which `FastMCP` was removed; the API is `from mcp.server import MCPServer` with
   `@mcp.tool()`. The pin is exact, not `>=`, because an unpinned dependency resolves to
   a future major and breaks on import. (An existing local project, `kali_mcp`, is
   already broken by exactly this: it imports the removed `mcp.server.fastmcp` and pins
   no upper bound.) The SDK also no longer reads `.env` files.

4. **VM names are resolved to `.vmx` paths through a closed allowlist; callers never
   supply paths.** Exactly one function maps a VM name to a path, against a pinned
   roster committed in the repository, with a `relative_to()` check against the lab root
   as defence in depth. A tool that accepted a caller-supplied path would be an
   arbitrary-file-primitive with a power switch on it. Paths are pinned, not discovered
   by globbing — a glob would happily accept a path outside the lab.

## Intended usage

The server is registered as a *local* stdio server in the opencode client config, as an
argument array rather than a shell string. Shape of the eventual config:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "vmware": {
      "type": "local",
      // PLACEHOLDER PATHS — this project's venv does not exist yet.
      // command[0] is the venv interpreter by absolute path so nothing
      // depends on PATH resolution.
      "command": [
        "D:\\llms\\models\\testing\\vm_mcp\\.venv\\Scripts\\python.exe",
        "-u",
        "D:\\llms\\models\\testing\\vm_mcp\\src\\vm_mcp\\server.py"
      ],
      "cwd": "D:\\llms\\models\\testing\\vm_mcp",
      "environment": {
        "VMRUN_PATH": "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe"
      },
      "enabled": true,
      "timeout": 15000
    }
  },
  "tools": {
    "vmware_list_vms": true,
    "vmware_vm_status": true,
    "vmware_host_resources": true,
    "vmware_guest_health": true,

    "vmware_start_vm": false,
    "vmware_stop_vm": false,
    "vmware_restart_vm": false
  }
}
```

Those paths are **placeholders**. No virtualenv has been created, no dependencies are
installed, and `src/vm_mcp/server.py` does not exist, so this block will not work as
written. `VMRUN_PATH` is pinned rather than discovered so the server cannot silently
bind to a different hypervisor install. `timeout` covers startup and the tools
handshake, not individual tool calls.

Note also that the mutating tools default to `false` above, and guest credentials are
optional environment variables — never committed to a config file.

## Lab

Target: the GOAD (Get Off Attack Domain) lab at `D:\vms\work_AD`, running on **VMware
Workstation 17.5.2**. Six VMs:

| VM | Role | Domain | vCPU | RAM |
|---|---|---|---|---|
| `GOAD-DC01` | domain controller | `sevenkingdoms.local` | 2 | 3000 MB |
| `GOAD-DC02` | domain controller | `north.sevenkingdoms.local` | 2 | 3000 MB |
| `GOAD-DC03` | domain controller | `essos.local` | 2 | 3000 MB |
| `GOAD-SRV02` | server | `north.sevenkingdoms.local` | 2 | 6000 MB |
| `GOAD-SRV03` | server | `essos.local` | 2 | 5000 MB |
| `PROVISIONING` | Linux jumpbox / provisioner (Ubuntu 22.04) | — | 2 | 2000 MB |

Two operational facts constrain the design and are worth knowing before reading any
future code. The full lab asks for ~21.5 GB of RAM against ~32 GB of physical memory
on a 4-core host, so all six VMs cannot be powered on at once — capacity reporting must
be honest per-VM rather than assume the lab fits. And a guest takes roughly 156 seconds
from power-on to a responsive SSH service, so a `start_vm` that returns in under two
seconds describes a VM that is useless for another two and a half minutes. Both are
why the health check exists and why the timings are measured rather than assumed.

## Build plan

The full build plan, findings, blockers and milestone breakdown live in **`PLAN.md`**.

`PLAN.md` and the `research/` directory are **local gitignored working documents**, not
deliverables. They are intentionally untracked: the plan churns daily and the research
directory is scratch material, so neither belongs in the repository's history. If you
are reading this on GitHub and want that context, it is on the author's machine.

## Repository scope

This repository currently contains documentation and git configuration only. Adding
`LICENSE`, CI and contributor documentation is deliberately deferred — there is nothing
to license or build yet, and inventing a license before the first line of code is
committed is a decision that should be made deliberately rather than by a scaffold.
