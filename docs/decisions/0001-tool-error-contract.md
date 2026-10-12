# ADR 0001: The tool-error contract — `is_error` vs `raise_exceptions`

- Status: Accepted
- Date: 2026-10-12
- Issue: [#3](https://github.com/work-ai-llm/vm_mcp/issues/3)
- Milestone: M1-1 - Read-only telemetry

## Context

While M0 was being built against the pinned `mcp==2.2.0`, one behaviour had to be
nailed down before the first real tools could be tested honestly.

`mcp.Client` defaults to `raise_exceptions=False`. A call to a tool that does not
exist, or to a tool with bad arguments, does **not** raise a Python exception. It
returns a normal `CallToolResult` with `is_error=True` and the message in
`content[0].text`:

```
bad tool    : is_error=True text='Unknown tool: does_not_exist'
bad args    : is_error=True text="...Input should be a valid integer..."
missing arg : is_error=True text="...Field required..."
```

The server logs to stderr and carries on serving. Nothing propagates to the
caller as an exception.

`PLAN.md` §4 (Safety model) asserted the opposite — "Tool errors are raised as
`MCPError`, never returned as success-shaped dicts." That claim was wrong on the
client side and had never been verified; it was inherited from an audit of a
different project. Left undecided, it produces tests that silently pass (a
`pytest.raises` that never fires), an unstated server-side convention, and an
unclear picture of what text actually reaches the model.

## Decision

1. **Tests assert at both layers, deliberately.** Protocol-layer tests assert on
   `CallToolResult.is_error` — that is what the model sees
   (`tests/test_mcp_server.py`, `test_unresolvable_call_comes_back_as_is_error`).
   Function-layer tests assert `pytest.raises(ToolError)`, because the handler
   raises *before* the SDK converts the raise into `is_error=True`
   (`tests/test_vm_mcp.py`). Neither layer alone is the whole contract.

2. **The server-side rule: tool handlers `raise ToolError`, never return
   error-shaped dicts.** `ToolError` comes from
   `mcp.server.mcpserver.exceptions`; the SDK documents that a raised `ToolError`
   makes the call return `is_error=True` with the message preserved in the
   content. `vm_status` follows this for every unresolvable identifier. The rule
   is asserted by
   `test_unresolvable_call_comes_back_as_is_error` and
   `test_tool_error_message_reaches_the_content`, and stated in the
   `vm_status` docstring.

3. **Validation errors are passed through raw.** Bad or missing arguments reach
   the model as the SDK's own pydantic text, not a hand-written summary.
   Summarising them is real work with little payoff at this surface, so it is
   deferred to M4 (hardening) rather than improvised here.

4. **Clients stay on the default `raise_exceptions=False`.** Any future
   non-stdio client takes the same posture: assert on `is_error`, do not expect
   a raise.

## Consequences

- **Failure and degradation are different things.** A tool that cannot reach
  VMware is *not* an error: `list_vms` returns the registered VMs it can read,
  every `power_state` marked `unknown`, plus `observed_via: "unavailable"`. That
  is a degraded answer, not a failed call, and it is asserted by
  `test_unreachable_vmrun_also_comes_back_as_a_value_not_an_error`. Only
  caller-facing mistakes (an identifier that does not resolve) become
  `is_error=True`. Collapsing the two would let a host fault read as a confident
  wrong answer.
- A deliberate failure keeps its own message after the SDK's prefix, which is
  why the message is written for the caller and tested
  (`test_tool_error_message_reaches_the_content`).
- The wider error-handling policy — what a bad argument should read like, and
  whether validation text is ever summarised — remains **M4**.

## See also

- `src/vm_mcp/server.py` — `vm_status` raises `ToolError` on a failed resolve.
- `tests/test_mcp_server.py` (header notes the three v2 API facts).
- `tests/test_vm_mcp.py` — the error-path tests above.
- Protocol-level `ping` is a separate, already-settled question: it was removed
  in the 2026-07-28 spec and `Client.send_ping()` fails with
  `MCPError("Method not found")`. Liveness is proven by `list_tools()` or a real
  tool call.
