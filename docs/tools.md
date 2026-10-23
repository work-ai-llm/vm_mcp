# Tools

How each shipped tool behaves and why. The tool names and the one-line
summaries are in the README; this is the detail. The read-only half is the
M1 trio plus `guest_health` from M3; the mutating half (`start_vm`,
`stop_vm`, `restart_vm`) is M2, in its own section further down.

EVERY tool carries annotations: the read-only tools carry
`ToolAnnotations(read_only_hint=True, destructive_hint=False)` (the
`READ_ONLY` constant), while `start_vm` is shipped `MUTATES` and
`stop_vm`/`restart_vm` are `DESTRUCTIVE` -- a `hard` stop risks guest
filesystem damage, so its risk label is not the same as the start's. A test
asserts that **every advertised tool** is described and annotated, and
asserts the read-only claim per tool, so a tool added without annotations
or with a lying one fails the suite rather than shipping silently.
Annotations are a label to the model, not access control (see
[`security.md`](security.md)).

## The shape rules

- **All values are structured** (dicts of JSON values). No prose is returned as
  data; the only free text is an explicit error string or a `*_error` field.
- **`vm_status` is a separate tool**, not a mode of `list_vms`: they differ in
  cost and shape. `list_vms` is one registry read and one `vmrun list` for the
  whole roster; `vm_status` resolves one VM and may also read its `.vmx` and call
  `checkToolsState`. Merging them would force the list call to carry per-VM detail
  an agent does not want in a loop.
- **Partial success, per tool.** `list_vms` degrades partially; `vm_status` fails
  as a whole. "Silently missing" is never an option.
- **Snapshots are excluded** — neither count nor names. `listSnapshots` is an
  extra per-VM `vmrun` call with no consumer in the read-only surface; a
  deliberate exclusion, revisited when a consumer needs it.

## `list_vms`

Takes no arguments. Reads the VMware library registry and asks VMware which VMs
are powered on.

```
vms          [{ name, uuid, power_state }, ...]   # every registered VM
counts       { total, running }
observed_via "vmrun-list" | "unavailable"
registry_error   (only when the registry is unreadable)
vmrun_error      (only when VMware could not be queried)
```

`power_state` is `running` / `stopped` / `unknown`. The `.vmx` path is omitted:
it can run to ~190 characters, no caller can act on it, and `vm_status` returns
it for the one VM you care about.

**Degrades partially:** if `vmrun` is unreachable, `list_vms` still returns the
registered VMs, each `power_state: unknown`, with `observed_via: "unavailable"`.
A host fault is a degraded answer, not a failed call, and is never reported as
"every VM is off".

## `vm_status`

Takes one `uuid` (preferred, unambiguous) or `name` (loose-matched).

```
name, uuid, vmx, power_state, vmx_exists
vcpu, mem_mb                      # configured, from the .vmx; absent if unread
guest_os, os_family               # from the .vmx, not the registry
tools_state                       # running | installed | undetermined
vmrun_error                       # only when VMware could not be queried
```

- `vcpu` / `mem_mb` are **configured** ceilings, not current usage; a stopped VM
  still reports them. They are omitted, not zeroed, when the `.vmx` was
  unreadable — absent is more honest than "0 GB".
- `os_family` maps VMware's vocabulary to a coarse family so "is this Windows?"
  does not require knowing VMware's strings; `otherlinux-64` maps to `linux`, and
  `unknown` is distinct from `other`.
- `tools_state` is only queried for a **running** VM. `checkToolsState` on a
  powered-off guest costs 0.65–3.5s to answer `installed`, which means nothing, so
  a stopped VM reports `undetermined (vm powered off)`.
- **Fails as a whole** on an unresolvable identifier (`is_error=True`); a status
  for the wrong VM is worse than no status. The message names what *is*
  registered, and no VMware process is started.

## `host_resources`

Takes no arguments. Reports measured host CPU, RAM and disk, plus what is left
after the lab. `headroom_gib` is host available memory minus the *configured*
memory of running VMs, and each running VM gets an `rss_gib`.

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
actually holds on the host now. They answer different questions, and GOAD-DC01
shows why: with VMware's own per-VM overhead counted, resident can exceed the
ceiling — and it can also sit far below it when a guest is idle or ballooned out.
`headroom_gib` subtracts the ceilings, so it is a worst case, not a prediction.

### Why there is no "will it fit" verdict

The question the tool most naturally invites — "can DC03 start?" — cannot be
answered from the host side. VMware's per-VM overhead is invisible outside the
hypervisor, so any single number would be a guess dressed as a measurement. The
tool reports the raw quantities the arithmetic needs and leaves the arithmetic to
the caller. (The GOAD lab alone asks ~21.5 GB against ~32 GB physical, so the lab
genuinely cannot all run at once — which is exactly why the arithmetic must be
honest rather than hidden.)

### Smaller behaviours worth knowing

- `rss_gib` is `null`, never `0`, when no host process can be matched to a
  running VM. That is "not measured", not "holding nothing"; the aggregate under
  `vmware` may still count that VM's process.
- `load_percent` is `null` when the sampling window caught no CPU counter ticks,
  which on Windows is routine at this window length. "Not measured", not zero.
- One unreadable volume carries `error` instead of numbers and does not affect the
  others. `E:\` on this host always fails this way.

### How per-VM RSS is attributed

`vmware-vmx.exe` is one process per running VM, and that process carries the VM's
`.vmx` path as the final argument on its command line. The host-side measurement
matches each `vmware-vmx` process to a registered VM by that path (case- and
slash-insensitive). A running VM with no matching process reports `rss_gib: null`
rather than guessing.

`rss_gib` is a host-side figure and says nothing about guest health. A VM far
below its ceiling may have a guest that is fine, or one that is out of memory
inside while costing the host nothing. Guest truth needs guest-side data.

## `guest_health`

Takes one `uuid` or `name` (loose-matched, like `vm_status`), plus an optional
`port` override. The verdict comes from a four-rung ladder, and the result
reports the highest rung an observation was made at — not just the verdict
([#12](https://github.com/work-ai-llm/vm_mcp/issues/12)):

| Rung | Observation | Verdict if it is the ceiling |
|---|---|---|
| power | in `vmrun list`? (`down` if not: vmrun answered and said off) | `down` |
| tools | `checkToolsState == running` — the hypervisor's view of the `vmtoolsd` heartbeat | `degraded` |
| address | a guest address the host can route to, discovered fresh each call | `degraded` |
| service | TCP connect to the guest's service port answers | `up` |

The order is by cost, and every rung needs no guest credentials. The
heartbeating rung is the key one for this lab: it is hypervisor-side, so it
works for every VM regardless of guest networking, and a frozen guest stops
reporting `running`.

### What is deliberately *not* a probe

- **ICMP is not used.** Nine minutes of `Test-Connection` loss was recorded
  against a demonstrably live guest; ping answers firewalls, not liveness. A
  raw-socket TCP connect was measured at ~90 ms, where
  `Test-NetConnection` costs 12-14 s per try — the probe is a bare `asyncio`
  connect with a 2 s ceiling, closed immediately, sending no data.
- **A guest op is not a readiness gate.** `listProcessesInGuest` answered
  t+2.4 s into a boot that physically needed 156 s, so a successful vmrun guest
  call proves nothing. Only the service rung answers `up`.
- **`getGuestIPAddress` output is a candidate, never a target.** vmrun reported
  the unroutable static GOAD address `192.168.230.3` for one lab VM and the
  host-reachable bridged DHCP address (`192.168.0.10`) for another. Every
  candidate is validated against the host's own on-link subnets first; the
  rejected ones come back under `rejected_addresses` instead of vanishing.

### Where the reachable address comes from

DHCP makes the bridged address change between boots, so discovery is per call.
Two credential-free sources, in order: `getGuestIPAddress`, then the Windows
neighbor cache (`arp -a`) matched by **MAC** — the `.vmx` declares each
adapter's MAC, so a cache entry naming that MAC is this guest's address. The
MAC match is what found the bridged address in the lab where vmrun reports
only the unroutable one, and it is also why discovery is hard to fool: a stale
entry, if probed, frames land on the VM's own NIC, which drops an IP it does
not own.

### Defaults, and what each boundary means

- **Ports by guest family:** Windows `3389` then `445` (a closed first port
  does not end the ladder — a DC with live SMB but no RDP is still up), Linux
  `22`, macOS `5900`. A family with no entry (and an unclassifiable `.vmx`)
  makes no probe at all and says so. `port` overrides the defaults.
- **`unknown` is not `down`.** `down` means VMware was asked and said the VM is
  off. `unknown` means VMware could not be asked at all; reporting `down`
  during a host fault would be a confident claim that every DC in the lab is
  powered off.
- **`refused` is kept visible.** A RST is the guest's own stack proving it is
  alive; that gateway answer is a `degraded` with the reason saying so, not an
  `unknown`.

Verified live against a powered-on GOAD DC from the host: `up`, reached
`service`, `TCP 3389 answered on 192.168.0.10 in 2 ms`, address via
`get-guest-ip` — with the same VM's wazuh manager, powered off, answered
`down` at the power rung in under a second.

## The mutating half (M2: `start_vm`, `stop_vm`, `restart_vm`)

The shape rules carry over: structured values, exit codes never trusted,
identifiers resolved through the registry only. What changes is risk. These
tools change the lab, so they ship **disabled by default** in
`opencode.jsonc` and carry risk annotations rather than the read-only pair.

### `start_vm`

Issues `vmrun start <vmx> nogui` and confirms the VM *registered as running*
by reading `vmrun list` back. It does not wait for the guest to be usable:
measured on this host, the start command returns in ~2s and the guest needs
~156s more before its services answer. `power_state: "running"` means
powered on, emphatically not ready. An agent wanting readiness polls the
read-only tools until `guest_health` ships to do it for it.

### `stop_vm`

`mode: "soft"` (default) issues `vmrun stop <vmx> soft` and answers
**immediately** with `power_state: "stopping"`, `confirmed: false` -- a state
the server commanded, not one it observed. That shape was forced by
measurement, not chosen: opencode enforces a per-server *request timeout*
(15000 ms in `opencode.jsonc`), the deadline sits on the response rather than
on idleness, and a direct probe killed a 12s tool call at a 5s timeout while
progress notifications were arriving every second. **No amount of waiting
done inside the call survives a deadline that short**, so the shutdown does
not happen inside the call: a background reaper task owns the spawned vmrun,
drains its pipes so they cannot wedge it on Windows, logs its eventual exit,
and kills it if it outlives the 960s ceiling. The agent confirms with
`vm_status`/`list_vms` -- the same observation job it already does after a
boot's ~156s.

- **One graceful stop per VM at a time.** A second soft stop while one is in
  flight *joins* it instead of spawning a second vmrun process against the
  same guest. The flight is keyed by normalized `.vmx` path and cleared by
  the reaper at the moment its vmrun exits, so a landed stop answers a
  repeat with the clean already-off no-op, not a stale `stopping`.
- **The flight guards in every direction.** While a shutdown is in flight,
  `start_vm` and a soft `restart_vm` are refused -- the one confused state
  the power tools will not create is a machine being told to go down and
  being told to come up at the same time. The refusal carries the flight's
  age and waits are stated as `vm_status` `stopped`; `mode: 'hard'` is the
  override named in the same breath, never refused, so the guard is a
  direction-sensitive one and never a lockout.
- **The flight claims at entry, before the pre-check.** A start handler in
  the same batch would otherwise read a clear registry inside the ~0.9s
  `is_running` window -- and a start accepted mid-shutdown was observed on
  this host to be queued by VMware and to materialize 70s after the guest
  had exited: a deferred power-on no call asked for, reported as two clean
  successes. The claim is synchronous against every other handler's read,
  released where its rationale ends (machine already off, spawn failed,
  hard concluded), and the reaper releases what its own vmrun keeps alive.
- **The per-call `detail` is a pointer, not the contract.** It names what
  the agent needs in the moment -- it did not wait, what `waited_s` means
  here, how to confirm -- and the full rationale lives in the tool
  description, which is in context at decision time. The tests budget its
  length so it cannot bloat its way back to a wall.
- **`hard` is never automatic.** A guest that refuses to leave is reported,
  never escalated: cutting power is the caller's deliberate follow-up, and
  the tool is annotated destructive because an unclean shutdown on a Windows
  domain controller risks guest filesystem damage.

### `restart_vm`

Takes `stop_vm`'s `mode`, reports the halves separately (`stopped`, then
`started`), and states its own flow in `stop_half` so nobody has to decode
result shapes:

| `stop_half` | Meaning | `started` |
|---|---|---|
| `done` | Both halves ran in the call: the VM was already off, or a `hard` stop confirmed and the start ran. | the start result |
| `handoff` | The soft shutdown is in flight. Poll `vm_status` to `stopped`, then call `start_vm`. | `null` |
| `blocked` | The hard stop did not confirm; the start was refused rather than power on over a possibly-running machine. | the refusal and its reason |

`started` is **always present**. A null is the handoff -- distinguishable
because `stop_half` says so -- never a lost field.

### `mode`, everywhere it appears

`mode` is matched case-insensitively: `Hard` is the request the caller
meant, and punctuation is not worth a failed power-off. Anything outside the
two values is rejected by a tool error that echoes the bad value and names
both valid values -- the same boundary discipline the name errors follow.
The schema advertises `mode` as an enum, so a model choosing it sees the
choices before it sends anything.

The tool shapes above were confirmed against the live host, not only in unit
tests: an unknown name is refused with no VMware process started, a powered-off VM
is answered rather than treated as missing, and an unreachable `vmrun` yields a
degraded value rather than an error. The power tools were verified live too --
start, graceful stop, hard stop, restart and idempotence against the
`PROVISIONING` jumpbox, lab left powered off and snapshot count unchanged --
but that pass ran against the earlier *blocking* build of the stop; the
fire-and-forget design above is test-verified, and a repeat live run against
a real guest is the natural next verification.
