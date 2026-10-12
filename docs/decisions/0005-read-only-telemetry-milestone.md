# ADR 0005: The read-only telemetry milestone

- Status: Complete
- Date: 2026-10-12
- Issue: [#10](https://github.com/work-ai-llm/vm_mcp/issues/10)
- Sub-issues: [#7](https://github.com/work-ai-llm/vm_mcp/issues/7),
  [#8](https://github.com/work-ai-llm/vm_mcp/issues/8),
  [#9](https://github.com/work-ai-llm/vm_mcp/issues/9)
- Milestone: M1-1 - Read-only telemetry

## Context

M1-1 was "build the three read-only telemetry tools". The three tool lines each
hid a decision, which is why the milestone shipped with three sub-issues rather
than a bare task list:

- what `list_vms` enumerates → **#7** (ADR 0002)
- how the server invokes `vmrun` → **#8** (ADR 0003)
- what each tool returns → **#9** (ADR 0004)

## Decision / outcome

The three tools shipped, read-only, with no mutating tool:

| Tool | Returns |
|---|---|
| `list_vms` | The roster and each VM's power state (ADR 0002, 0004). |
| `vm_status` | One VM's detail (ADR 0004). |
| `host_resources` | Measured host CPU/RAM/disk, per-VM RSS, headroom (`docs/host_resources.md`). |

Commits: `2b4fe89` (`list_vms`, `vm_status`), `86861f8` (`host_resources`),
`eb599df` (doc correction), `003772a` (per-VM RSS), `c195e41` (clean Ctrl+C).
The suite is **132 tests, all passing**, with no VMware process started by the
tests.

### Annotations are part of the contract

Every tool carries `ToolAnnotations(read_only_hint=True, destructive_hint=False)`
(the `READ_ONLY` constant). A test asserts that **every advertised tool** is
read-only, so a tool added without annotations fails the suite rather than
shipping silently (`test_every_tool_is_advertised_as_read_only`). Annotations are
a label to the model, not access control — the structural controls are the closed
roster and the `vmrun` layer. See `docs/security.md`.

### A note on containment

Issue #10's work-confirmation asked that "the resolved path [be] refused if it
escapes the lab root". There is **no lab-root prefix check**, and that is
intentional: ADR 0002 chose to enumerate every registered VM, so the server has no
notion of "the lab root". Containment is provided by the **closed roster** instead
— exactly one function (`roster.resolve`) maps a caller identifier to a path, and
it only ever returns a path the registry itself lists. A caller-supplied `.vmx`
path can never reach `vmrun`. That is the property that matters, and it holds
without a lab-root check. A future mutating tool inherits the same boundary; its
allowlist is issue [#15](https://github.com/work-ai-llm/vm_mcp/issues/15).

### Negative paths were exercised against the real lab

Deciding a failure should happen is not the same as confirming it does. Each of
the following was run against the live host, not only asserted in the unit tests:

- unknown VM name → refused, no VMware process started
  (`test_unknown_identifier_starts_no_process`);
- powered-off VM → answered, not treated as missing;
- `vmrun` unreachable → degraded value with `power_state: unknown`, not an error.

## Consequences

- M1 is complete; the mutating half is not written, by design.
- Guest health / liveness (`guest_health`) is **not** here — it is M3, and it is
  gated on a host networking problem that is still open.

## See also

- ADR 0001 (tool-error contract), 0002 (roster), 0003 (vmrun), 0004 (shapes).
- `docs/host_resources.md`, `docs/security.md`.
