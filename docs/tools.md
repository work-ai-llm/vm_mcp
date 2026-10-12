# Tools

How each read-only tool behaves and why. The tool names and the one-line
summaries are in the README; this is the detail. M1 shipped exactly three — no
mutating tool exists.

Every tool carries `ToolAnnotations(read_only_hint=True, destructive_hint=False)`
(the `READ_ONLY` constant), and a test asserts that **every advertised tool** is
read-only, so a tool added without annotations fails the suite rather than
shipping silently. Annotations are a label to the model, not access control (see
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

## Not in this milestone

- **`guest_health`** — the liveness ladder. The reason the project exists: it must
  separate "powered on" from "actually responsive", so a VM that is up but wedged
  reports `degraded`, not `up`. It is M3.
- **`start_vm` / `stop_vm` / `restart_vm`** — the mutating half, deliberately
  unwritten. The allowlist that gates it is
  [#15](https://github.com/work-ai-llm/vm_mcp/issues/15), and the mutating tools
  are intended to ship disabled by default in client configuration (see
  [`security.md`](security.md)).

The tool shapes above were confirmed against the live host, not only in unit
tests: an unknown name is refused with no VMware process started, a powered-off VM
is answered rather than treated as missing, and an unreachable `vmrun` yields a
degraded value rather than an error.
