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

**M1 complete: three read-only tools, `list_vms`, `vm_status` and `host_resources`. No mutating tool exists.**

Every tool in this repository is read-only. None can change a VM's power
state, and the test suite never touches VMware — 124 tests pass with no VMware
process started. The mutating half is deliberately not written yet; the
allowlist that has to gate it is [#15](https://github.com/work-ai-llm/vm_mcp/issues/15).

| Tool | Kind | Shipped |
|---|---|---|
| `list_vms` | read-only | The lab roster and each VM's power state. |
| `vm_status` | read-only | One VM's power state, vCPU, RAM, guest OS, VMware Tools state. |
| `host_resources` | read-only | Measured host CPU, RAM and disk, plus per-VM resident memory and headroom. |
| `guest_health` | read-only | Liveness ladder. Distinguishes `up` / `degraded` / `down` / `unknown` and reports how far up the ladder it got. |
| `start_vm` | mutating | Power on, optionally waiting for the guest to become ready. |
| `stop_vm` | mutating | Power off. Graceful by default; hard-off is opt-in. |
| `restart_vm` | mutating | Stop then start a single VM. |

### `host_resources` attributes memory, and refuses to judge it

The tool returns `headroom_gib` — host available memory minus the *configured*
memory of running VMs — and a per-VM `rss_gib` for each running VM. There is no
"will another VM fit" field, deliberately, because VMware's per-VM overhead is
not observable from outside the hypervisor. It is also per-VM rather than
per-byte, so it grows with the *count* of VMs and not their size.

Measured on this host with three VMs running:

```
                            configured    rss_gib
wazuh-4.7.5                    8.00          7.13
provider: GOAD-DC01            2.93          4.53   <- resident exceeds its ceiling
provider: PROVISIONING         1.95          1.10
                            ---------     --------
configured total              12.88            --
resident total                   --         12.77
```

`configured_gib` is the ceiling in the VM's `.vmx`; `rss_gib` is what the VM
actually holds on the host right now. They answer different questions, and
GOAD-DC01 shows why: with VMware's own per-VM overhead counted, resident can
exceed the ceiling — and it can also sit far below it when a guest is idle or
ballooned out. `headroom_gib` subtracts the ceilings, so it is a worst case,
not a prediction. Every number the alternative would need is in the payload;
the tool declines to pick between them.

`rss_gib` is a host-side figure and says nothing about guest health. A VM far
below its ceiling may have a guest that is fine, or one that is out of memory
inside while costing the host nothing. Guest truth needs guest-side data, which
is M2's `guest_health`.

Smaller behaviours worth knowing:

- `rss_gib` is `null`, never `0`, when no host process can be matched to a
  running VM. That is "not measured", not "holding nothing", and the aggregate
  under `vmware` may still count that VM's process.
- `load_percent` is `null` when the sampling window caught no CPU counter ticks,
  which on Windows is routine at this window length. That is "not measured", not
  zero.
- One unreadable volume carries `error` instead of numbers and does not affect
  the others. `E:\` on this host always fails this way.

The mutating tools are intended to ship disabled by default in client configuration,
gated behind an explicit per-agent opt-in. `guest_health` is the reason the project
exists: it must separate "powered on" from "actually responsive", so a VM that is up
but wedged reports as `degraded`, not `up`.

The research that the design is based on — every control operation this server
intends to wrap, executed against the real lab with timings recorded — lives in
`PLAN.md` and `research/`, and is deliberately untracked.

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

2. **Two transports over one tool surface, loopback-only by default.** stdio is the default
   because it opens no port: the client spawns the process and owns its lifetime, so a
   server that can power off a domain controller is not sitting on a socket waiting for
   anything. `--transport http` exists for a different reason: a client that should not
   control the server's lifetime, and a second machine that needs to reach the same
   server. The server binds `127.0.0.1` by default. Widening the bind address to
   `0.0.0.0` is a deliberate flag and is not reachable by accident, because the whole
   threat this project is aimed at is a prompt-injected agent deciding to power off a DC.
   Both transports expose an identical tool surface, so nothing in a tool definition
   knows or cares which one carried the call.

3. **The MCP Python SDK is pinned to v2 (`mcp==2.2.0`).** v2 is a breaking rewrite in
   which `FastMCP` was removed; the API is `from mcp.server import MCPServer` with
   `@mcp.tool()`. The pin is exact, not `>=`, because an unpinned dependency resolves to
   a future major and breaks on import. (An existing local project, `kali_mcp`, is
   already broken by exactly this: it imports the removed `mcp.server.fastmcp` and pins
   no upper bound.) The SDK also no longer reads `.env` files.

4. **Callers never supply paths. Names resolve through the live VMware registry.**
   Exactly one function (`roster.resolve`) maps a caller-supplied identifier to a VM,
   and it only ever returns a path that the registry itself lists. A tool accepting a
   caller-supplied path would be an arbitrary-file-primitive with a power switch on it.
   The registry is `%APPDATA%\VMware\inventory.vmls` — the same file the GUI reads to
   build its library — so the roster is discovered rather than pinned in the repository.
   Paths are still never globbed: a glob would happily accept a path outside the lab.

   What the registry does *not* carry is a power state, so `vmrun` supplies that. One
   `vmrun list` call serves the whole roster. If `vmrun` cannot be reached, power state
   is `unknown` for every VM and never `stopped` — collapsing those two would report a
   powered-on domain controller as off during a host fault.

   The registry's free-text `guest` field is **not** read. It is wrong on 3 of the 8 VMs
   on this host (three Server 2019 machines labelled "windows server 2016"), so only
   machine-written identity fields are trusted; guest OS comes from the `.vmx`.

   UUIDs are the one unambiguous key: the registry's `UUID` equals the `.vmx` `uuid.bios`
   on all 8 VMs, and it survives a display-name rename. Names are matched loosely as a
   convenience — `GOAD-DC01` resolves the VM the registry calls `provider: GOAD-DC01`,
   because refusing correct input over a prefix makes a tool unusable rather than safe.
   An ambiguous match is an error listing candidates, never a guess.

## Usage

The server is registered in **`opencode.jsonc` at the repository root** — project-local,
version-controlled, and travelling with the code. It is *not* written into the user's
global config at `C:\Users\Zver\.config\opencode\`.

Two ways to run it, and the choice determines how the client behaves.

### Remote (what the committed config uses)

Start the server yourself; opencode only connects.

```powershell
# Terminal 1 — the server, running independently
..\.venv\Scripts\vm-mcp.exe --transport http

# equivalently, without relying on the console script being installed:
..\.venv\Scripts\python.exe -m vm_mcp --transport http

# or, needing neither the console script nor the editable install:
python vm_mcp.py --transport http

# Terminal 2 — opencode, from this directory
opencode
```

The venv lives at `..\.venv`, one level above the repository, so that it is the project's
single shared environment rather than an asset of the main checkout. Activate it with
`..\.venv\Scripts\Activate.ps1`.

### Launching from a worktree

`vm_mcp.py` at the repository root is a launcher, and it is the one to use when working
in a [git worktree](https://git-scm.com/docs/git-worktree). The other two forms resolve
the package through the venv's `__editable__*.pth`, which names exactly one checkout —
so in a second worktree they would quietly run the *first* worktree's code.

`vm_mcp.py` puts its own `src` ahead of that, so each worktree runs its own code, and the
one shared `.venv` is enough for all of them:

```powershell
git worktree add ..\feature-x -b feature-x
..\.venv\Scripts\python.exe ..\feature-x\vm_mcp.py --transport http
```

No `pip install -e .` per worktree. `research\` and `PLAN.md` live one level above the
repository, outside Git, and are reached from any worktree as `..\research\` and
`..\PLAN.md`.

### One consequence of the launcher's name

`vm_mcp.py` sits beside the package it imports, so it shadows it for anything that has the
repository root on `sys.path` and does a bare `import vm_mcp`. From the repository root:

```powershell
python -m vm_mcp --help            # fine -- runpy executes the launcher
python -c "import vm_mcp"          # ModuleNotFoundError: 'vm_mcp' is not a package
python vm_mcp.py --help            # fine -- the launcher inserts src ahead of itself
pytest                             # fine -- pyproject sets pythonpath = ["src"]
```

`python -c "import vm_mcp"` is the only casualty, and it is a diagnostic one-liner rather
than a launch path. `import vm_mcp` from any other directory is unaffected.

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "vmware": {
      "type": "remote",
      "url": "http://127.0.0.1:8765/mcp",
      "enabled": true,
      "timeout": 15000
    }
  }
}
```

There is no `command` and no `cwd` here, because opencode is not running anything. It
holds a URL. Consequences worth being explicit about: the server outlives any client,
several clients can share one server, and a crash in opencode cannot take the lab tools
down. The flip side is that the server must be started separately — with nothing running
on the port, opencode reports `✗ failed` and offers no tools.

### Local stdio (spawned by the client)

```jsonc
{
  "mcp": {
    "vmware": {
      "type": "local",
      "command": [
        "D:\\llms\\models\\testing\\vm_mcp\\.venv\\Scripts\\vm-mcp.exe"
      ],
      "cwd": "D:\\llms\\models\\testing\\vm_mcp\\vm_mcp",
      "enabled": true,
      "timeout": 15000
    }
  }
}
```

`command` is an argument array, not a shell string: element 0 is the executable, the rest
are its arguments. `cwd` is the working directory the process is started in, which is what
relative paths inside the server resolve against. The absolute interpreter path is
deliberate, so nothing depends on `PATH` resolution finding the right Python.

### How the model learns what to call

Worth being clear about, because the config does not say it. The config only says **where
the server is**. The tool surface is discovered at runtime: opencode performs the MCP
handshake, the server answers `tools/list` with a name, a description and a JSON Schema
per tool, and opencode puts those into the model's context as callable functions. The
model picks from what was advertised; it is not guessing and nothing is hardcoded
client-side. The SDK derives the schema from the Python signature and the docstring,
which is why the docstrings on `list_vms` and `vm_status` are written as tool
documentation rather than as code comments.

### Transports and settings

`--transport stdio` (the default), `--host`, `--port`, `--path`. Defaults come from
module constants at the top of `src/vm_mcp/server.py` — `DEFAULT_HTTP_HOST`,
`DEFAULT_HTTP_PORT`, `DEFAULT_HTTP_PATH` — and are printed on every HTTP start:

```
--transport stdio   (default)   client launches the process; no port is opened
--host    127.0.0.1             loopback: only this machine can reach it
--port    8765
--path    /mcp                  arbitrary; the client is handed the URL
```

The endpoint path is not fixed by the protocol. `/mcp` is the SDK's convention, not a
requirement — `--path /vm_run_mcp` works identically, because the client is simply
given that URL. Distinct paths are how you would route several servers behind one
reverse proxy later.

**There is no environment-variable configuration.** Settings live in the source file
on purpose. An environment variable is invisible configuration: it gets set in a shell
profile, outlives the reason it was set, and the server then listens somewhere the
source does not mention. A regression test pins that behaviour, so `VM_MCP_*` in the
environment cannot change how the server starts.

## Security posture

**HTTP transport currently has no authentication.** No token, no TLS, no client identity
check. Anything that can reach the socket can call every tool the server exposes. The
server says so on startup, in the banner, on every HTTP launch — because the tool surface
is about to include power-off, and "I bound it to loopback" is a mitigation, not a control.
Authentication has to be settled before the bind is widened off this machine.

The mutating tools are intended to ship disabled by default in client configuration,
gated behind an explicit per-agent opt-in — the `tools` block, not the server, is where
that switch lives:

```jsonc
"tools": {
  "vmware_list_vms": true,
  "vmware_vm_status": true,

  "vmware_start_vm": false,
  "vmware_stop_vm": false,
  "vmware_restart_vm": false
}
```

Tool annotations are hints to the model about what a call does. They are **not** access
control: nothing enforces them, they carry no authorisation, and a caller that ignores
them gets the same response. The real controls are the registry-backed resolution that
turns a VM name into a path, the no-shell subprocess layer, and this client-side gating.

The plan is to reach the server from a second machine over Tailscale. That is a
bind-address change (`--host 0.0.0.0`) plus an authentication story, not a redesign —
which is the main reason the HTTP transport exists alongside stdio. Guest credentials,
when they are needed, are environment variables and never belong in a committed config.

## Lab

Target: the GOAD (Get Off Attack Domain) lab on **VMware Workstation 17.5.2**. The live
registry has **8 VMs**, not the 6 the original plan assumed — the wazuh monitor and the
Ubuntu 22.04 image VM were already registered on this host:

| Registry name | Role | vCPU | RAM | Guest OS |
|---|---|---|---|---|
| `provider: GOAD-DC01` | domain controller, `sevenkingdoms.local` | 2 | 3000 MB | Windows Server 2019 |
| `provider: GOAD-DC02` | domain controller, `north.sevenkingdoms.local` | 2 | 3000 MB | Windows Server 2019 |
| `provider: GOAD-DC03` | domain controller, `essos.local` | 2 | 3000 MB | Windows Server 2019 |
| `provider: GOAD-SRV02` | server, `north.sevenkingdoms.local` | 2 | 6000 MB | Windows Server 2019 |
| `provider: GOAD-SRV03` | server, `essos.local` | 2 | 5000 MB | Windows Server 2019 |
| `provider: PROVISIONING` | Linux jumpbox / provisioner (Ubuntu 22.04) | 2 | 2000 MB | Ubuntu 22.04 |
| `wazuh-4.7.5` | Wazuh manager | 4 | 8192 MB | Linux (unclassified by VMware) |
| `Ubuntu_20.04.4_VM_LinuxVMImages.COM` | stock Ubuntu image | 2 | 4096 MB | Ubuntu 20.04 |

Note the `provider: ` prefix: that is Vagrant's naming, not VMware's, and it is why
`vm_status(name="GOAD-DC01")` has to work as well as the registry's own spelling. The
Server 2019 labels come from each `.vmx`; the registry's own `guest` field claims 2016
for three of them and is not read.

The GOAD lab alone asks for ~21.5 GB of RAM against ~32 GB of physical memory on a
4-core host, so all five lab VMs cannot be powered on at once — capacity reporting must
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

This repository currently contains the server, its tests and its project-local opencode
config. Adding `LICENSE`, CI and contributor documentation is deliberately deferred —
there is nothing to license or build yet, and inventing a license before the first line
of code is committed is a decision that should be made deliberately rather than by a
scaffold.
