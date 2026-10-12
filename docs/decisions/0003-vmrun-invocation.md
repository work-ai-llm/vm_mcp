# ADR 0003: How the server invokes `vmrun`

- Status: Accepted
- Date: 2026-10-12
- Issue: [#8](https://github.com/work-ai-llm/vm_mcp/issues/8)
- Milestone: M1-1 - Read-only telemetry
- Implementation: `src/vm_mcp/vmrun.py`

## Context

Every tool reaches VMware by running `vmrun.exe` as a subprocess. The baseline —
"assume `vmrun` is on the machine, point the server at it, call it the way a user
would" — is sound and was verified (a `subprocess` call returned byte-identical
output to a PowerShell run), but it leaves four small questions open. This ADR
answers all four and records that the answers live in one shared module, written
before the second tool existed.

## Decision

**One module, `vmrun.py`, is the only place `vmrun.exe` is executed.** It exposes
`run_vmrun()` (the primitive), plus `list_running_vmx()` and `tools_state()`. All
read-only tools call it; none builds its own command line.

### Binary location and the missing-binary case

- **Pinned absolute path**, `VMRUN_PATH` =
  `C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe`. A pinned path is
  predictable; `PATH` resolution would let a different `vmrun` win silently.
- Overridable **per call** (`run_vmrun(..., executable=...)`), which is how tests
  avoid depending on the real path.
- **Missing binary fails the call, not startup.** `run_vmrun` raises
  `VmrunUnavailable("vmrun not found at ...")` when the file is absent. Startup
  stays cheap and import-time work stays off the critical path (OpenCode budgets
  5000 ms for the `tools/list` handshake).

### Concurrency: unconstrained

No global lock, no per-VM lock. Six VMs, sub-second read-only calls. A global
lock would let one stuck call block every tool, which is the exact failure the
timeout is there to prevent; the lock would re-introduce it more broadly. Each
call is its own short-lived process.

### Timeouts

Per-command ceilings: `DEFAULT_TIMEOUT = 20.0s`, `LIST_TIMEOUT = 15.0s`, chosen
well above measured cold-start times (0.55s for `list`, 0.65–3.5s for
`checkToolsState`). A hung `vmrun` is killed (`process.kill()`) and reported.

**A timeout is distinguishable from a non-zero exit.** A timeout raises
`VmrunUnavailable("vmrun <sub> timed out after <n>s")`; a non-zero exit returns
`VmrunResult(ok=False, exit_code=...)`, and `list_running_vmx` turns a failed
exit into `VmrunUnavailable("vmrun list failed (exit N)")`. The caller can tell
"we could not ask" from "we asked and it errored", and neither is ever returned
as an empty success.

### Argument vector, not a shell

`asyncio.create_subprocess_exec(*command)` — never `shell=True`. A VM named
`a & b` is one argument, not a command injection. The command is
`[<vmrun>, "-T", "ws", *args]`; `-T ws` pins the target to the local Workstation
instance so `vmrun` does not stall probing for a VIX/network server.

### Output decoding

`vmrun` writes its own errors to **stdout** (not stderr) with exit code `-1`, and
this host runs a cp866 console. So both streams are captured, decoded as UTF-8
with replacement, and merged; the caller can then match `Error:` without knowing
that quirk.

## Consequences

- One place to fix if VMware changes the command line or output format; the raw
  output is logged at debug level to make a format change diagnosable.
- Two facts from the M2 (power control) work are anticipated, not blocked: a
  longer per-call `timeout=` can be passed, and nothing here precludes a
  hard-stop flag. Neither is built yet.
- The error-reporting contract on top of these calls is ADR 0001.

## See also

- `src/vm_mcp/vmrun.py` — module docstring lists the four traps in full.
- `src/vm_mcp/server.py` — `_power_states()` is the one caller of
  `list_running_vmx()`; `vm_status` calls `tools_state()` only for a running VM.
- Commit `2b4fe89`.
