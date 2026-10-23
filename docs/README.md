# vm_mcp documentation

Design notes for the server. The top-level
[`README.md`](../README.md) is the quick start; this directory is the reasoning.

- [`architecture.md`](architecture.md) — the long-lived decisions: why `vmrun`,
  the two transports, the SDK pin, the registry and roster (#7), the `vmrun`
  layer (#8), and the tool-error contract (#3).
- [`tools.md`](tools.md) — how each shipped tool behaves and why (#9 for the
  read-only half; the mutating half and its contracts from M2), including the
  `host_resources` internals and the `guest_health` ladder (#12).
- [`usage.md`](usage.md) — running the server, the client config, worktrees,
  transports.
- [`security.md`](security.md) — the security posture and the real controls.

Each issue-tagged decision links the GitHub issue it resolves, so a "why is it
like this?" question has an on-repo answer instead of a closed issue.
