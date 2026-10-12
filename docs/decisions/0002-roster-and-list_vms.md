# ADR 0002: What `list_vms` enumerates — the roster

- Status: Accepted
- Date: 2026-10-12
- Issue: [#7](https://github.com/work-ai-llm/vm_mcp/issues/7)
- Milestone: M1-1 - Read-only telemetry
- Implementation: `src/vm_mcp/roster.py`

## Context

`vmrun list` reports only the **running** set. With the lab powered down it
returns `Total running VMs: 0` — an empty list, not an error — so on its own it
cannot tell "the VM is off" apart from "the VM does not exist". `list_vms` needs
a roster from a second source.

Three candidates were considered and two rejected:

- `vmrun list` alone — cannot answer existence.
- Globbing the filesystem for `*.vmx` — finds VMs deleted years ago, misses VMs
  outside the searched tree, and carries no identity or power state.
- A hardcoded allowlist — wrong for a shared server; it encodes one operator's
  lab layout into an artifact others run, and reports "unknown VM" for every VM
  the caller actually owns.

## Decision

**The roster is the VMware Workstation registry**, `%APPDATA%\VMware\inventory.vmls`
— the same file the GUI reads to build its library. It is parsed read-only by
`roster.py`:

- It is INI-style `key = "value"`, not JSON despite the `.vmls` name. Its first
  line is `.encoding = "windows-1251"`, so decoding is driven by that directive
  rather than assumed.
- Identity is `vmlist<N>.config` (absolute `.vmx` path), `.DisplayName` and
  `.UUID`. Blocks with an empty config are stubs and are skipped.
- The free-text `guest` and `notes` fields are **not read**. They are user-typed,
  they rot, and they were verified wrong on 3 of the 8 VMs on this host (three
  Server 2019 machines labelled "windows server 2016"). Only machine-written
  identity fields are trusted; guest OS comes from the `.vmx`.

The registry is re-read on **every call**, never cached. It is ~7 KB and parses
in well under a millisecond; caching saved nothing measurable and created an
order-dependent failure mode where `list_vms` and `vm_status` could disagree
about which VMs exist.

### Out-of-lab VMs are **not** excluded

The registry is not scoped to the lab: on this host it lists 8 VMs, including the
Wazuh manager and a stock Ubuntu image. `list_vms` reports **all 8**. This
deliberately reverses the framing in issue #7 ("8 VMs where the answer is 6").

The tool's promise is "every VM registered with VMware Workstation", not "the
lab". A lab filter would require a lab definition the server does not have, and
any definition baked in would lie the moment it runs on a different machine.
Lab membership stays the caller's concern; the honest answer is the full
registry.

### A missing `.vmx` is reported, not hidden

A registry entry can outlive its `.vmx` (the VM was moved or deleted without
updating the inventory). This is reported rather than omitted or treated as
fatal: `vm_status` sets `vmx_exists: false` for such an entry, and `list_vms`
still lists it. Because it is not in the running set, its `power_state` reads
`stopped`, and `vmx_exists` is what separates "gone" from "off".

### Names: report the registry's spelling, accept the common ones

Output uses the registry's display name (`provider: GOAD-DC01`). Resolution
accepts loose aliases so a caller is not forced to reproduce the `provider: `
prefix: the prefix-stripped name and the `.vmx` filename stem both match,
case-insensitively. An ambiguous match is an error listing the candidates, never
a guess. See ADR 0003 for how a resolved name becomes a `vmrun` argument.

## Consequences

- **Missing is distinguishable from powered-off** — `vmx_exists` vs
  `power_state` (the last `Done when` item in #7).
- **A broken registry fails closed.** If the file is unreadable, the snapshot
  carries an `error`; `list_vms` returns `registry_error` and an empty list
  rather than reporting "no VMs", and `resolve()` raises. The server never fails
  open by accepting an unverified identifier.
- **UUID is the only unambiguous key.** It equals the `.vmx` `uuid.bios` and
  survives a display-name rename. A UUID that matches nothing is an error, never
  a fallback to name matching — see `docs/security.md`.
- Registry paths are Vagrant-managed and per-machine, which is exactly why the
  roster is discovered at runtime instead of committed. A hand-committed roster
  would go stale after a lab rebuild; the registry does not.

## See also

- `src/vm_mcp/roster.py` — `registry()`, `resolve()`, `parse_inventory()`.
- `src/vm_mcp/server.py` — `list_vms` docstring and the `registry_error` path.
- Commit `2b4fe89` (read-only `list_vms`/`vm_status` over the registry),
  `16c67e5` and `2ef9feb`.
