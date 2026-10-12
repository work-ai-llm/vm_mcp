# `host_resources`

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
is `guest_health` (M3).

## Smaller behaviours worth knowing

- `rss_gib` is `null`, never `0`, when no host process can be matched to a
  running VM. That is "not measured", not "holding nothing", and the aggregate
  under `vmware` may still count that VM's process.
- `load_percent` is `null` when the sampling window caught no CPU counter ticks,
  which on Windows is routine at this window length. That is "not measured", not
  zero.
- One unreadable volume carries `error` instead of numbers and does not affect
  the others. `E:\` on this host always fails this way.

## How per-VM RSS is attributed

`vmware-vmx.exe` is one process per running VM, and that process carries the
VM's `.vmx` path as the final argument on its command line. The host-side
measurement matches each `vmware-vmx` process to a registered VM by that path
(case- and slash-insensitive). A running VM with no matching process reports
`rss_gib: null` rather than guessing.

## Why no "will it fit" verdict

The question `host_resources` most naturally invites — "can DC03 start?" —
cannot be answered from the host side. VMware's per-VM overhead is invisible
outside the hypervisor, so any single number the tool could print would be a
guess dressed as a measurement. The tool reports the raw quantities the
arithmetic needs and leaves the arithmetic to the caller.

The mutating tools are intended to ship disabled by default in client
configuration, gated behind an explicit per-agent opt-in (see
[`security.md`](security.md)). `guest_health` is the reason the project exists:
it must separate "powered on" from "actually responsive", so a VM that is up but
wedged reports as `degraded`, not `up`.
