# vm_mcp documentation

Design notes and decision records for the server. The top-level
[`README.md`](../README.md) is the quick start; this directory is the reasoning.

## Decision records

Architectural decisions are recorded as short ADRs. Each is dated and links the
GitHub issue it resolves, so a "why is it like this?" question has an on-repo
answer instead of a closed issue.

| ADR | Decision | Issue |
|---|---|---|
| [0001](decisions/0001-tool-error-contract.md) | Tool errors: `is_error` vs `raise_exceptions` | [#3](https://github.com/work-ai-llm/vm_mcp/issues/3) |
| [0002](decisions/0002-roster-and-list_vms.md) | What `list_vms` enumerates — the roster | [#7](https://github.com/work-ai-llm/vm_mcp/issues/7) |
| [0003](decisions/0003-vmrun-invocation.md) | How the server invokes `vmrun` | [#8](https://github.com/work-ai-llm/vm_mcp/issues/8) |
| [0004](decisions/0004-tool-return-shapes.md) | What each read-only tool returns | [#9](https://github.com/work-ai-llm/vm_mcp/issues/9) |
| [0005](decisions/0005-read-only-telemetry-milestone.md) | The read-only telemetry milestone | [#10](https://github.com/work-ai-llm/vm_mcp/issues/10) |

The `0005` record is the milestone itself: the three tools shipped, the
annotations contract, the containment boundary, and the negative paths that were
exercised against the real lab.

## Reference

In-depth material that used to live in the README:

- [`design.md`](design.md) — the standing architecture decisions (why `vmrun`,
  why two transports, why the SDK is pinned).
- [`usage.md`](usage.md) — running the server, the client config, worktrees,
  transports.
- [`security.md`](security.md) — the security posture and the real controls.
- [`host_resources.md`](host_resources.md) — the host-capacity tool, per-VM RSS,
  and the decision not to compute "will it fit".
- [`lab.md`](lab.md) — the live lab inventory the tools are tested against.
