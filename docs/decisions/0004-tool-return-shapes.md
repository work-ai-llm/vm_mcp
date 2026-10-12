# ADR 0004: What each read-only tool returns

- Status: Accepted
- Date: 2026-10-12
- Issue: [#9](https://github.com/work-ai-llm/vm_mcp/issues/9)
- Milestone: M1-1 - Read-only telemetry
- Implementation: `src/vm_mcp/server.py`

## Context

The three tool names were settled; what they return was not. Every field returned
is context the model pays for on every request, and the model cannot ask a
follow-up about a field it was never given — so a guessed shape frozen into tests
is how the wrong shape becomes permanent. This ADR records the shapes as the
contract.

## Decision

**All values are structured.** Each tool returns a dict of JSON values. Prose is
not returned as data; the only free text is an explicit error string (e.g. an
undetermined `tools_state`) or a `*_error` field, never a sentence the model has
to parse.

### `list_vms` (no arguments)

```
vms          [{ name, uuid, power_state }, ...]   # every registered VM
counts       { total, running }
observed_via "vmrun-list" | "unavailable"
registry_error   (only when the registry is unreadable)
vmrun_error      (only when VMware could not be queried)
```

`power_state` is `running` / `stopped` / `unknown`. The `.vmx` path is
deliberately omitted: it can run to ~190 characters, no caller can act on it, and
`vm_status` returns it for the one VM you care about.

### `vm_status` (one VM, by `uuid` or `name`)

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
  powered-off guest costs 0.65–3.5s to answer `installed`, which means nothing,
  so a stopped VM reports `undetermined (vm powered off)` instead.

### `host_resources` (no arguments)

Measured host CPU, RAM and disk, plus what is left after the lab. Full detail and
the decision *not* to compute "will another VM fit" are in
`docs/host_resources.md`; the shape is `cpu`, `memory`, `volumes`, `vmware`
(aggregate resident), `vm_memory` (per-VM configured + `rss_gib`), `headroom_gib`.

### Two shapes, two tools

`vm_status` stays a **separate tool**, not a mode of `list_vms`. They differ in
cost and shape: `list_vms` is one registry read and one `vmrun list` for the whole
roster; `vm_status` resolves one VM and may additionally read its `.vmx` and call
`checkToolsState`. Merging them would force the list call to carry per-VM detail
an agent does not want in a loop.

### Partial success, per tool

`list_vms` **degrades partially**: if `vmrun` is unreachable it still returns the
registered VMs, each `power_state: unknown`, with `observed_via: "unavailable"`.
`vm_status` **fails as a whole** on an unresolvable identifier (`is_error=True`),
because a status for the wrong VM is worse than no status. "Silently missing" is
never a third option.

### Snapshots: excluded

Snapshots are **not** in the M1 surface — neither count nor names. `listSnapshots`
is an extra per-VM `vmrun` call (and the multiple costs of `vmrun` are measurable:
`checkToolsState` alone runs to 3.5s cold) with no consumer in the read-only
telemetry surface. This is a deliberate exclusion, not an oversight; it is
revisited when a consumer actually needs it.

## Consequences

- The shapes above are the contract the tools are tested against
  (`tests/test_vm_mcp.py`).
- Field-set changes are a documented decision here first, so a new field is added
  on purpose rather than drifting in.

## See also

- `src/vm_mcp/server.py` — the docstrings on `list_vms`, `vm_status`,
  `host_resources` are the model-facing copy of this contract.
- `docs/host_resources.md` — the `host_resources` deep dive.
- Commits `2b4fe89` (`list_vms`, `vm_status`), `86861f8` (`host_resources`).
