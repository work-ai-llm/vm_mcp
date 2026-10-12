"""Power control primitives: start, stop, restart, and how each is *observed*.

This module is where M2's real decision lives, and the decision was forced by a
measurement rather than chosen.

The tension
-----------
`vmrun start <vmx> nogui` returns in ~2s. `vmrun stop <vmx> hard` returns in
~0.9s. Neither of those numbers tells the caller whether the machine did what was
asked, because both commands report on the *request*, not the *outcome*:

* `start` exits 0 while the guest is still 150 seconds from being usable.
* `stop soft` does not return until the guest has fully shut down -- measured at
  **26.3s** for the Ubuntu jumpbox -- so it cannot be polled while it runs if it
  is simply awaited.

So both directions need the same missing ingredient: a way to ask VMware what is
actually true, right now. That is `vmrun list`, which reports power state from
the hypervisor rather than from the request we just made.

The observation rule
--------------------
**A command's exit code is not evidence that its effect happened.** Every function
here treats the post-condition -- "does this VM appear in `vmrun list`?" -- as the
answer, and the command's own exit code as corroboration only. A start that
returns exit 0 but does not appear is reported as a failure, because from the
caller's point of view it *was* one: the VM is not running.

This is the same discipline `list_vms` already follows in the opposite direction,
where an unreachable vmrun yields `unknown` rather than `stopped`. Here it stops a
successful-looking command from being reported as a completed power cycle.

Shutdown timing, and why it is a ladder
---------------------------------------
Shutdown duration is guest-dependent and genuinely unknown ahead of time: a
Linux jumpbox is not a Windows domain controller draining Active Directory, and
nothing in the `.vmx` predicts which is which. Rather than guess a single
timeout, `stop` polls on an escalating ladder -- 10s, 30s, 60s, 120s -- spending
almost nothing in the common case (a Linux guest is down at the first poll) while
still covering a slow Windows shutdown inside a single tool call.

The ladder is a *ceiling on patience*, not a plan to escalate. When it is
exhausted the VM is still running and the answer says so, along with the
recommendation to retry with `hard`. This code never escalates to a hard power
cut on its own: a graceful shutdown failing is a reason to report, not a reason
to pull the plug on a machine the caller did not ask us to unplug.

`hard` is never used as a fallback, deliberately. Escalating silently would make
`stop_vm` a destructive tool wearing the name of a polite one, and the filesystem
damage risk of an unclean shutdown is exactly the thing a caller should decide
about rather than inherit.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from vm_mcp.vmrun import (
    STOP_HARD,
    STOP_HARD_TIMEOUT,
    STOP_SOFT,
    VmrunResult,
    VmrunUnavailable,
    _collect,
    list_running_vmx,
    power_on,
    run_vmrun,
    spawn_vmrun,
)

__all__ = [
    "POWER_RUNNING",
    "POWER_STOPPED",
    "POWER_UNKNOWN",
    "PowerOutcome",
    "is_running",
    "start",
    "stop",
    "restart",
]

logger = logging.getLogger(__name__)

POWER_RUNNING = "running"
POWER_STOPPED = "stopped"

# The VM's state could not be determined at all. Distinct from both of the above:
# "stopped" and "not running" are not the same claim when vmrun could not be
# reached, and reporting either one would be a confident wrong answer to a
# question about a domain controller's power state.
POWER_UNKNOWN = "unknown"

# Escalating poll schedule for a graceful stop, in seconds *from the request*.
#
# Chosen as a shape rather than as measurements, because the durations are
# guest-dependent and unmeasurable in advance (see module docstring). The
# property that matters is that cost tracks the actual wait: a guest that shuts
# down in 8s costs one 10s poll, while a slow Windows domain controller still
# gets 220s of patience and is reported on rather than abandoned. Four polls
# rather than a continuous poll, so an unresponsive guest produces a handful of
# `vmrun list` calls instead of hundreds.
SOFT_STOP_LADDER: tuple[int, ...] = (10, 30, 60, 120)

# How long to wait for a VM to appear in `vmrun list` after a start.
#
# `vmrun start` returns only once the VM is powered on, so this exists to catch
# the case where the command succeeded and the VM still did not register -- not to
# wait out the ~156s boot. That wait is deliberately not here; see `start`.
START_SETTLE_TIMEOUT = 15.0

# How often to re-check `vmrun list` while waiting for the start to register.
_START_POLL_INTERVAL = 0.5


@dataclass(frozen=True)
class PowerOutcome:
    """What actually happened, as distinct from what was requested.

    Attributes:
        power_state: `running` or `stopped`, **observed** from `vmrun list`.
            Never inferred from the exit code of the command.
        confirmed: False when the post-condition could not be observed at all --
            vmrun could not be queried, or the wait ran out. The caller must
            treat this as "state unknown", not as `power_state`.
        waited_s: Seconds spent waiting to observe the post-condition. Reported
            so an agent can reason about cost rather than guess at it.
        vmrun_error: The failure, when there is one.
        detail: Human-readable note about anything unusual -- a graceful stop
            that ran out of patience, or a start that did not register.
    """

    power_state: str
    confirmed: bool
    waited_s: float
    vmrun_error: str | None = None
    detail: str | None = None

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "power_state": self.power_state,
            "confirmed": self.confirmed,
            "waited_s": round(self.waited_s, 1),
        }
        if self.vmrun_error:
            payload["vmrun_error"] = self.vmrun_error
        if self.detail:
            payload["detail"] = self.detail
        return payload


def _norm(path: str | Path) -> str:
    """Normalize a `.vmx` path for comparison against `vmrun list` output.

    Verified: on this host the paths vmrun prints match the registry byte for
    byte, so this is insurance against a future release changing slash direction
    or case rather than a workaround for an observed mismatch. The same helper
    exists in `server.py`; it is duplicated here rather than imported so that
    this module stays independent of the tool layer.
    """
    return str(path).replace("/", "\\").lower()


async def is_running(
    vmx_path: str | Path,
    *,
    executable: Path | None = None,
) -> tuple[bool | None, str | None]:
    """Is this VM powered on, according to `vmrun list`?

    Args:
        vmx_path: Absolute path to the VM's `.vmx`.

    Returns:
        `(True|False, None)` when VMware answered, or `(None, error)` when it
        could not be reached.

    The tri-state is the whole point. A missing VM from `vmrun list` and an
    unqueryable vmrun both "look" like absence from a list, and collapsing them
    would let a host fault be reported as a successfully stopped domain
    controller.
    """
    try:
        running = await list_running_vmx(executable=executable)
    except VmrunUnavailable as exc:
        return None, str(exc)
    return _norm(vmx_path) in {_norm(p) for p in running}, None


async def start(
    vmx_path: str | Path,
    *,
    executable: Path | None = None,
    settle_timeout: float = START_SETTLE_TIMEOUT,
) -> PowerOutcome:
    """Power on a VM and confirm it registered as running.

    Issues `vmrun start <vmx> nogui`, then polls `vmrun list` until the VM appears
    or `settle_timeout` expires.

    `settle_timeout` is a confirmation window, not a boot wait. The VM is powered
    on before `start` returns, so this is only catching a VM that failed to
    register at all. **A confirmed `running` here means "powered on", emphatically
    not "usable"** -- the measured gap to a responsive guest is ~156s on this host.
    Callers wanting readiness must poll for it.

    Returns:
        A PowerOutcome whose `power_state` was read back from VMware.

    Raises:
        VmrunUnavailable: The start command itself could not be issued.
    """
    started = time.monotonic()

    result = await power_on(vmx_path, executable=executable)
    if not result.ok:
        return PowerOutcome(
            power_state=POWER_STOPPED,
            confirmed=False,
            waited_s=time.monotonic() - started,
            vmrun_error=_describe(result),
            detail=(
                "vmrun start failed; the VM was not powered on. Nothing was "
                "changed by this call beyond the failed request."
            ),
        )

    running, error = await _await_running(vmx_path, settle_timeout, executable)

    if running is True:
        return PowerOutcome(
            power_state=POWER_RUNNING,
            confirmed=True,
            waited_s=time.monotonic() - started,
            detail=(
                "powered on. The guest is not usable yet -- expect roughly "
                "150s more before its OS finishes booting and services answer. "
                "Poll vm_status for tools_state rather than assuming readiness."
            ),
        )

    if running is False:
        # Exit 0 and no VM in the running list. These disagree, and the
        # observation is what counts.
        return PowerOutcome(
            power_state=POWER_STOPPED,
            confirmed=True,
            waited_s=time.monotonic() - started,
            detail=(
                "vmrun start reported success but the VM did not appear in "
                "vmrun list within "
                f"{settle_timeout:.0f}s. Treat this as a failed start."
            ),
        )

    return PowerOutcome(
        power_state=POWER_UNKNOWN,
        confirmed=False,
        waited_s=time.monotonic() - started,
        vmrun_error=error,
        detail=(
            "the start command succeeded but the power state could not be "
            "confirmed; vmrun could not be queried afterwards."
        ),
    )


async def stop(
    vmx_path: str | Path,
    *,
    mode: str = STOP_SOFT,
    ladder: Sequence[int] | None = None,
    executable: Path | None = None,
) -> PowerOutcome:
    """Power off a VM, gracefully by default, and confirm it actually went down.

    `mode="soft"` asks the guest OS to shut itself down and is the default
    because it lets the filesystem unmount cleanly. `mode="hard"` cuts power.

    Neither mode is escalated to by this function. If a graceful stop runs out of
    patience the result says the VM is still running and recommends `hard`; it
    does not pull the plug itself. See the module docstring for why.

    Args:
        vmx_path: Absolute path to the VM's `.vmx`.
        mode: `soft` (default) or `hard`.
        ladder: Cumulative seconds at which to check whether the VM is down.
            Only consulted for a graceful stop. Defaults to `SOFT_STOP_LADDER`,
            resolved at call time rather than as a default argument so that
            overriding the module constant actually takes effect.
        executable: Override the vmrun binary path. Tests use this.

    Returns:
        A PowerOutcome. For a graceful stop that timed out, `power_state` is
        `running` and `detail` explains the recommendation.

    Raises:
        VmrunUnavailable: The stop command itself could not be issued.
        ValueError: `mode` is not one of the two supported values.
    """
    if mode not in (STOP_SOFT, STOP_HARD):
        raise ValueError(f"stop mode must be {STOP_SOFT!r} or {STOP_HARD!r}, not {mode!r}")

    if ladder is None:
        ladder = SOFT_STOP_LADDER

    started = time.monotonic()

    # Stopping an already-stopped VM is the desired end state, and vmrun reports
    # it as an error: `Error: The virtual machine is not powered on`. Surfacing
    # that would make a routine no-op look like a failure in the result an agent
    # reads -- and `restart_vm` on a stopped VM hits it every time. Checked first,
    # so the common idempotent case costs one `vmrun list` and returns cleanly.
    running, error = await is_running(vmx_path, executable=executable)
    if running is False:
        return PowerOutcome(
            power_state=POWER_STOPPED,
            confirmed=True,
            waited_s=time.monotonic() - started,
            detail="the VM was already powered off; nothing to stop.",
        )
    if running is None:
        # Cannot see the VM. Proceed anyway: the stop is the caller's request, and
        # a host fault must not turn "stop this VM" into a silent no-op that
        # reports success without having checked anything.
        logger.warning(
            "stop: could not read power state before stopping (%s); proceeding",
            error,
        )

    if mode == STOP_HARD:
        return await _stop_and_confirm_hard(vmx_path, started, executable=executable)

    # The graceful path is self-contained: `_stop_soft` walks the ladder while the
    # blocking command runs and returns the finished outcome, including what to do
    # if patience ran out. There is nothing left to confirm afterwards, and asking
    # again would double the cost of the common case for no new information.
    return await _stop_soft(vmx_path, ladder=ladder, executable=executable)


async def _stop_and_confirm_hard(
    vmx_path: str | Path,
    started: float,
    *,
    executable: Path | None = None,
) -> PowerOutcome:
    """Cut power, then confirm the VM actually left `vmrun list`.

    `stop hard` is measured at ~1s and returns as soon as power is cut. That is a
    report on the request, not the outcome, so it gets the same observation-based
    treatment as everything else.
    """
    result = await _stop_hard(vmx_path, executable=executable)

    if not result.ok:
        # A failed stop may still have worked. Ask, rather than assuming either way.
        running, error = await is_running(vmx_path, executable=executable)
        return PowerOutcome(
            power_state=POWER_UNKNOWN if running is None else (
                POWER_RUNNING if running else POWER_STOPPED
            ),
            confirmed=running is not None,
            waited_s=time.monotonic() - started,
            vmrun_error=_describe(result) or error,
            detail=(
                "vmrun stop hard failed. The power state above was read back from "
                "vmrun list, not inferred from the command's exit code."
            ),
        )

    running, error = await _await_stopped(
        vmx_path, STOP_HARD_TIMEOUT, interval=0.5, executable=executable
    )

    if running is True:
        return PowerOutcome(
            power_state=POWER_RUNNING,
            confirmed=True,
            waited_s=time.monotonic() - started,
            detail=(
                "vmrun stop hard reported success but the VM is still listed as "
                f"running after {STOP_HARD_TIMEOUT:.0f}s. It may be wedged; "
                "check vm_status before assuming it is off."
            ),
        )
    if running is False:
        return PowerOutcome(
            power_state=POWER_STOPPED,
            confirmed=True,
            waited_s=time.monotonic() - started,
        )
    return PowerOutcome(
        power_state=POWER_UNKNOWN,
        confirmed=False,
        waited_s=time.monotonic() - started,
        vmrun_error=error,
        detail="the stop command reported success but the power state could not be confirmed.",
    )


async def restart(
    vmx_path: str | Path,
    *,
    mode: str = STOP_SOFT,
    executable: Path | None = None,
) -> tuple[PowerOutcome, PowerOutcome]:
    """Stop a VM, then power it back on.

    Both halves report independently, and a stop that only partly worked is not
    papered over by a successful start. `restart` is two operations wearing one
    name; collapsing their outcomes into a single verdict would hide exactly the
    case where a VM was asked to restart and came back up without having cleanly
    stopped -- which is the case where a domain controller is holding stale
    state.

    Args:
        vmx_path: Absolute path to the VM's `.vmx`.
        mode: Stop mode, as for `stop`.

    Returns:
        `(stop_outcome, start_outcome)`.

    Raises:
        VmrunUnavailable: A command could not be issued.
        ValueError: `mode` is invalid.
    """
    stopped = await stop(vmx_path, mode=mode, executable=executable)

    # Do not power on a VM that is still running: that would turn a failed stop
    # into a confused double-boot rather than reporting the failure.
    if stopped.power_state != POWER_STOPPED:
        return stopped, PowerOutcome(
            power_state=stopped.power_state,
            confirmed=False,
            waited_s=0.0,
            detail=(
                "the VM was not confirmed stopped, so it was not started again. "
                "A restart requires a clean stop first; forcing power on over a "
                "running VM would produce a machine that looks up and is not."
            ),
        )

    started = await start(vmx_path, executable=executable)
    return stopped, started


# --- graceful stop internals ----------------------------------------------


async def _stop_soft(
    vmx_path: str | Path,
    *,
    ladder: Sequence[int] | None = None,
    executable: Path | None = None,
) -> PowerOutcome:
    """Run a graceful stop while polling `vmrun list` alongside it.

    `vmrun stop soft` blocks until the guest has shut down (measured 26.3s on this
    host), so it is **spawned rather than awaited**. Polling has to happen
    concurrently: awaiting the command first would mean no observation is possible
    until the answer is already known, and the ladder would be dead code.

    The process is always reaped. On the timeout path it is killed rather than
    left running, so a stop that outlives its patience does not leave a vmrun
    holding the VM in the background after the tool has returned.
    """
    started = time.monotonic()

    if ladder is None:
        ladder = SOFT_STOP_LADDER

    process = await spawn_vmrun(
        ["stop", str(vmx_path), STOP_SOFT], executable=executable
    )

    deadline_total = float(sum(ladder)) if ladder else 0.0
    # The command's own ceiling, kept separate from the ladder's: whichever is
    # longer governs. vmrun exiting non-zero is surfaced, not swallowed.
    command_task = asyncio.ensure_future(
        _collect(process, ["stop", str(vmx_path), STOP_SOFT], deadline_total + 60.0)
    )

    elapsed = 0.0
    try:
        for checkpoint in ladder:
            await asyncio.sleep(max(0.0, checkpoint - elapsed))
            elapsed = time.monotonic() - started

            running, error = await is_running(vmx_path, executable=executable)

            if running is False:
                # The post-condition is satisfied. Reap the command so the stop
                # result is reported rather than abandoned mid-flight.
                return await _finish(command_task, process, PowerOutcome(
                    power_state=POWER_STOPPED,
                    confirmed=True,
                    waited_s=time.monotonic() - started,
                ))

            if running is None:
                # vmrun is unreachable while a shutdown is in progress. That is
                # more likely a host fault than a VM problem, and it must not be
                # reported as either.
                return PowerOutcome(
                    power_state=POWER_UNKNOWN,
                    confirmed=False,
                    waited_s=time.monotonic() - started,
                    vmrun_error=error,
                    detail=(
                        "the graceful stop was issued but vmrun could not be "
                        "queried to confirm it. The VM's state is unknown; "
                        "re-check with vm_status."
                    ),
                )

        # Ladder exhausted. The VM is still running, which is a real answer.
        return await _finish(command_task, process, PowerOutcome(
            power_state=POWER_RUNNING,
            confirmed=True,
            waited_s=time.monotonic() - started,
            detail=(
                f"still running {deadline_total:.0f}s after a graceful shutdown "
                "request, so the guest has not completed it. This often means a "
                "shutdown is waiting on something -- a prompt, a hung service, "
                "or a filesystem that will not flush. The VM is up and "
                "reachable as it was. Retry with mode='hard' to cut power; that "
                "risks guest filesystem damage, so it is left to the caller to "
                "choose."
            ),
        ))
    finally:
        if not command_task.done():
            command_task.cancel()
            await _reap(process)


async def _stop_hard(
    vmx_path: str | Path, *, executable: Path | None = None
) -> VmrunResult:
    """`vmrun stop <vmx> hard`, which returns as soon as power is cut (~1s)."""
    return await run_vmrun(
        ["stop", str(vmx_path), STOP_HARD],
        timeout=STOP_HARD_TIMEOUT,
        executable=executable,
    )


async def _finish(
    task: "asyncio.Future[VmrunResult]",
    process: "asyncio.subprocess.Process",
    outcome: PowerOutcome,
) -> PowerOutcome:
    """Reap a spawned stop command and fold its exit code into `outcome`.

    The observation is authoritative and already decided by the time this runs;
    the command's exit code can only add information, never overturn it. A
    non-zero exit *after* the VM was observed going down is therefore reported as
    a detail rather than as a failure -- the machine is off, and saying so would
    be a lie about the only fact that matters here.
    """
    try:
        result = await asyncio.wait_for(task, timeout=30.0)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        await _reap(process)
        return outcome

    if result.ok:
        return outcome

    # `outcome.detail` is optional, and the ladder-exhausted path is the one that
    # sets it. Interpolating a missing detail produced a literal "None Note: ..."
    # in a result an agent has to read, which is worse than no note at all.
    note = (
        "vmrun itself exited non-zero while this was happening; the power state "
        "above was still read back from VMware."
    )
    detail = f"{outcome.detail} {note}" if outcome.detail else note

    return PowerOutcome(
        power_state=outcome.power_state,
        confirmed=outcome.confirmed,
        waited_s=outcome.waited_s,
        vmrun_error=_describe(result),
        detail=detail,
    )


async def _reap(process: "asyncio.subprocess.Process") -> None:
    """Kill a spawned vmrun if it is still running, and wait for it to go.

    Leaving a vmrun behind holding a VM after the tool has returned is the failure
    this exists to prevent: the caller is told the stop timed out, retries, and
    now two processes are contending for one VM.
    """
    if process.returncode is not None:
        return
    try:
        process.kill()
        await process.wait()
    except (ProcessLookupError, asyncio.CancelledError):
        pass


# --- polling helpers ------------------------------------------------------


async def _await_running(
    vmx_path: str | Path,
    timeout: float,
    executable: Path | None,
) -> tuple[bool | None, str | None]:
    """Poll until the VM appears in `vmrun list` as running, or time out."""
    deadline = time.monotonic() + timeout
    while True:
        running, error = await is_running(vmx_path, executable=executable)
        if running is not None:
            return running, error
        if time.monotonic() >= deadline:
            return None, error
        await asyncio.sleep(_START_POLL_INTERVAL)


async def _await_stopped(
    vmx_path: str | Path,
    timeout: float,
    *,
    interval: float,
    executable: Path | None,
) -> tuple[bool | None, str | None]:
    """Poll until the VM disappears from `vmrun list`, or time out."""
    deadline = time.monotonic() + timeout
    while True:
        running, error = await is_running(vmx_path, executable=executable)
        if running is not None:
            return running, error
        if time.monotonic() >= deadline:
            return None, error
        await asyncio.sleep(interval)


def _describe(result: VmrunResult) -> str:
    """Render a vmrun failure as a message worth showing a caller.

    vmrun puts its errors on stdout with exit -1 (see the note in `vmrun.py`), so
    the message is in `result.stdout` and is frequently the only useful text
    there is. `Error: Cannot open VM: <path>` is the shape a caller needs to see
    verbatim, because it names the path VMware rejected.
    """
    text = (result.stdout or "").strip()
    head = " ".join(text.split())[:400]
    return head or f"vmrun exited {result.exit_code}"