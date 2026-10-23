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

Shutdown, and why a soft stop does not wait
-------------------------------------------
`vmrun stop soft` blocks until the guest has actually shut down -- measured
26.3s on the Ubuntu jumpbox, 61s on a busier one -- and the duration is
guest-dependent and unknowable in advance: a Linux jumpbox is not a Windows
domain controller draining Active Directory, and nothing in the `.vmx`
predicts which is which.

An earlier build held the tool call open and polled `vmrun list` on an
escalating ladder -- 10s, 30s, 60s, 120s -- so it could report the finished
outcome. That was cut for a reason measured rather than assumed: the client
enforces a per-server **request timeout** (`timeout` in `opencode.jsonc`,
15000 ms here), and the deadline sits on the response, not on idleness. A
graceful stop can outlive it no matter how the inside of the call spends the
time -- a direct probe killed a 12s tool call at a 5s client timeout while
progress notifications were arriving every second. Waiting inside the call
buys a report the caller has already abandoned.

So the soft path is issue-and-return, mirroring what `start_vm` already does
with the ~156s boot: the shutdown is requested, `vmrun` itself blocks on the
guest until it finishes, the result reports `stopping` immediately, and the
agent observes the outcome with the read-only tools instead. The spawned
vmrun is not abandoned -- a background task owns it until it exits or hits
the ceiling, after which it is killed rather than left holding the VM.

`hard` is never used as a fallback, deliberately. A graceful shutdown that
has not landed is reported, not escalated: silently pulling the plug would
make `stop_vm` a destructive tool wearing the name of a polite one, and the
filesystem damage risk of an unclean shutdown is exactly the thing a caller
should decide about rather than inherit. That decision is now the agent's,
made when it sees a VM still running after a soft request.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, replace
from pathlib import Path

from vm_mcp.vmrun import (
    STOP_HARD,
    STOP_HARD_TIMEOUT,
    STOP_SOFT,
    STOP_SOFT_TIMEOUT,
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
    "POWER_STOPPING",
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

# A graceful shutdown has been *requested and handed to VMware* -- this is a
# state this module commanded, not one it observed (it does not come from
# `vmrun list`), and `confirmed` is False while it holds. The guest may keep
# running for another minute as it goes down. Only a soft stop produces it;
# the read-only tools report `running` until the guest finishes leaving.
POWER_STOPPING = "stopping"

# How long to wait for a VM to appear in `vmrun list` after a start.
#
# `vmrun start` returns only once the VM is powered on, so this exists to catch
# the case where the command succeeded and the VM still did not register -- not to
# wait out the ~156s boot. That wait is deliberately not here; see `start`.
START_SETTLE_TIMEOUT = 15.0

# How often to re-check `vmrun list` while waiting for the start to register.
_START_POLL_INTERVAL = 0.5

# Ceiling for a graceful stop running in the background with no call waiting on
# it, counted against the spawned vmrun itself. VMware does the waiting
# host-side; this only bounds how long the process may be *owned here* before
# it is killed. 900s covers a Windows domain controller draining AD -- the
# thing a soft stop exists to do well -- so a slow-but-real shutdown must not
# be murdered at 15 seconds' worth of client patience.
SOFT_STOP_CEILING = STOP_SOFT_TIMEOUT + 60.0

# Live handles for the fire-and-forget reapers, so they cannot be garbage
# collected mid-shutdown. Entries are discarded the moment their task finishes;
# `stop` adds, the done-callback removes.
_BACKGROUND: set["asyncio.Task[None]"] = set()

# Graceful shutdowns already requested by someone, keyed by normalized `.vmx`
# path. Two concurrent soft stops for one VM would spawn two vmrun processes
# driving the same guest down -- wasted work at best, an interference risk at
# worst -- so a second soft stop while one is in flight *joins* it and issues
# nothing. Entries are cleared by the reaper's done-callback when the stop
# lands, when it is killed at the ceiling, or when vmrun reports a failure;
# after that the next soft request is genuinely new and spawns again. The
# value is the initiating call's outcome, dropped in for whoever joins.
_SOFT_STOPS_IN_FLIGHT: "dict[str, PowerOutcome]" = {}

# The joiner's detail. Separate from the initiating stop's wording because it
# answers a different question: not "will you stop my VM" but "did you just
# start a second stop for my VM".
_JOIN_DETAIL = (
    "A graceful shutdown for this VM is already in flight; this call "
    "issued no new one. Check vm_status: once it reads 'stopped', the VM "
    "is off."
)


@dataclass(frozen=True)
class PowerOutcome:
    """What actually happened, as distinct from what was requested.

    Attributes:
        power_state: `running` or `stopped`, **observed** from `vmrun list`;
            `unknown` when nothing can be observed; or, for one case only, a
            soft stop's `stopping` -- a state this module commanded rather
            than read back, always paired with `confirmed=False`.
        confirmed: False when the post-condition could not be observed at all --
            vmrun could not be queried, the wait ran out, or (soft stop) the
            observation has deliberately been left to a later, read-only
            call. The caller must treat this as "state unknown", not as
            `power_state`.
        waited_s: Seconds spent waiting to observe the post-condition. Reported
            so an agent can reason about cost rather than guess at it.
        vmrun_error: The failure, when there is one.
        detail: Human-readable note about anything unusual -- a shutdown in
            flight, or a start that did not register.
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
    executable: Path | None = None,
) -> PowerOutcome:
    """Power off a VM: gracefully by default, without waiting for the guest.

    `mode="soft"` asks the guest OS to shut itself down and **returns before
    the shutdown finishes** -- that is the point, see the module docstring on
    the client's request timeout. `mode="hard"` cuts power (measured ~1s) and
    is verified inside the call, because it is fast enough to be.

    Neither mode is escalated to by this function. A soft shutdown that has
    not landed is the caller's to observe with the read-only tools, and hard
    is the caller's deliberate second call.

    Args:
        vmx_path: Absolute path to the VM's `.vmx`.
        mode: `soft` (default) or `hard`.
        executable: Override the vmrun binary path. Tests use this.

    Returns:
        A PowerOutcome whose `power_state` says exactly what was verified:

        * `soft` on a running VM: `stopping`, `confirmed=False` -- a shutdown
          request is in flight, the call did not wait for it.
        * `soft` on a VM that was already off: `stopped`, `confirmed=True`.
        * `hard`: `stopped` confirmed by reading `vmrun list`, `running` if
          the VM is inexplicably still up, or `unknown`.

    Raises:
        VmrunUnavailable: The stop command itself could not be issued.
        ValueError: `mode` is not one of the two supported values.
    """
    if mode not in (STOP_SOFT, STOP_HARD):
        raise ValueError(f"stop mode must be {STOP_SOFT!r} or {STOP_HARD!r}, not {mode!r}")

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

    if mode == STOP_HARD:
        # Unobservable state also proceeds here, as it always has: hard is
        # fast, and the outcome below is observed whatever the pre-check saw.
        return await _stop_and_confirm_hard(vmx_path, started, executable=executable)

    # The VM is -- as far as anything can be seen -- powered on. Hand the
    # graceful shutdown to VMware and answer immediately; even when the
    # pre-check was blind (running is None, vmrun list itself failed), the
    # request is still issued, because a host fault must not silently turn
    # "stop this VM" into a no-op that reports success without checking. The
    # result carries `confirmed=False` either way: nothing here has seen the
    # guest go down.
    return await _initiate_soft_stop(
        vmx_path, started, precheck_error=error, executable=executable
    )


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
) -> tuple[PowerOutcome, PowerOutcome | None, str]:
    """Stop a VM, then power it back on -- or hand the start back to the caller.

    Both halves report independently, and a stop that only partly worked is not
    papered over by a successful start. See the docstring on `stop`: a soft
    shutdown runs in the background now, so `restart` with `mode="soft"` cannot
    confirm the VM is down inside its own call -- and starting a VM that is
    still shutting down is precisely the confused state this module refuses to
    create.

    Args:
        vmx_path: Absolute path to the VM's `.vmx`.
        mode: Stop mode, as for `stop`.

    Returns:
        `(stop_outcome, start_outcome, stop_half)`. `start_outcome` is None
        when the start was not issued; `stop_half` names the flow so no reader
        has to infer it from which keys happen to be present:

        * `"done"` -- both halves ran inside the call. The VM was found
          already off (no stop issued, start immediate), or a `mode="hard"`
          stop confirmed and the start ran. `start_outcome` carries whatever
          the start observed.
        * `"handoff"` -- a `mode="soft"` stop on a running VM. The shutdown is
          in flight in the background; the start is deliberately left to the
          caller, who issues `start_vm` once the read-only tools show
          stopped. Nothing here outruns the shutdown it just asked for.
        * `"blocked"` -- `mode="hard"` whose stop did not confirm. The
          refusal outcome below rides in `start_outcome` rather than a start
          over a possibly-running machine.

    Raises:
        VmrunUnavailable: A command could not be issued.
        ValueError: `mode` is invalid.
    """
    if mode not in (STOP_SOFT, STOP_HARD):
        raise ValueError(
            f"restart mode must be {STOP_SOFT!r} or {STOP_HARD!r}, not {mode!r}"
        )

    stopped = await stop(vmx_path, mode=mode, executable=executable)

    if stopped.confirmed and stopped.power_state == POWER_STOPPED:
        # A confirmed stop means the VM is down *right now* -- which, before
        # any soft stop was issued, is exactly the "already off" case. The
        # restart completes here and cheaply.
        return stopped, await start(vmx_path, executable=executable), "done"

    if mode == STOP_SOFT:
        # A graceful shutdown is in flight in the background. The caller
        # finishes the restart: poll vm_status until 'stopped', then start_vm.
        # Short by design -- the stop result's detail and the tool's
        # description already say why; this names only the missing step.
        note = (
            "This is half a restart: the shutdown is in flight. When "
            "vm_status reads 'stopped' (typically 30-90s), call start_vm "
            "to finish it."
        )
        detail = f"{stopped.detail} {note}" if stopped.detail else note
        return replace(stopped, detail=detail), None, "handoff"

    # `hard`: the stop ran, blocked, and did not come back confirmed. Refuse
    # the start rather than power on over a machine that may still be running:
    # a double-boot is not a restart, and no report says when it is safe.
    refusal = PowerOutcome(
        power_state=stopped.power_state,
        confirmed=False,
        waited_s=0.0,
        detail=(
            "the VM was not confirmed stopped, so it was not started again. "
            "A restart requires a clean stop first; forcing power on over a "
            "running VM would produce a machine that looks up and is not."
        ),
    )
    return stopped, refusal, "blocked"


# --- graceful stop internals ----------------------------------------------


async def _initiate_soft_stop(
    vmx_path: str | Path,
    started: float,
    *,
    precheck_error: str | None = None,
    executable: Path | None = None,
) -> PowerOutcome:
    """Issue `vmrun stop <vmx> soft` and answer before the guest obeys.

    `vmrun stop soft` blocks until the guest has shut down (measured 26.3s on
    this host, 61s on a busier one), so the command is handed to a background
    task that owns it -- `_collect` reads its pipes so they cannot fill (see
    the note in `vmrun.py`), `vmrun` itself drives the guest to shutdown, and
    if the stop outlives `SOFT_STOP_CEILING` the process is killed rather than
    left holding the VM in a half-commanded state.

    The tool call returns the moment the request is in flight. What the guest
    did about it is not known until some later observation -- which is why
    `confirmed` is False and `power_state` is `stopping`, a state this module
    commanded rather than one read back from VMware.

    One stop per VM at a time: a second soft stop for a VM whose shutdown is
    already in flight joins the existing one rather than spawning a second
    vmrun process against the same guest.
    """
    key = _norm(vmx_path)
    if key in _SOFT_STOPS_IN_FLIGHT:
        return PowerOutcome(
            power_state=POWER_STOPPING,
            confirmed=False,
            waited_s=time.monotonic() - started,
            vmrun_error=precheck_error,
            detail=_JOIN_DETAIL,
        )

    # Claim the slot before the first await. Above the check and the spawn
    # there is an interleaving window between concurrent calls -- the event
    # loop can run another coroutine between this function's awaits -- and a
    # check-then-register placed the wrong way round would let both calls
    # through. Claiming first makes the window zero wide: at most one call
    # ever holds a given key. Releasing on a failed spawn keeps a crashed
    # startup from permanently pinning the VM into "already stopping".
    _SOFT_STOPS_IN_FLIGHT[key] = PowerOutcome(
        power_state=POWER_STOPPING, confirmed=False, waited_s=0.0
    )
    args = ["stop", str(vmx_path), STOP_SOFT]
    try:
        process = await spawn_vmrun(args, executable=executable)
    except Exception:
        _SOFT_STOPS_IN_FLIGHT.pop(key, None)
        raise

    task = asyncio.create_task(_reap_background_stop(process, args))
    _BACKGROUND.add(task)
    task.add_done_callback(_BACKGROUND.discard)
    task.add_done_callback(lambda _t, _key=key: _SOFT_STOPS_IN_FLIGHT.pop(_key, None))

    return PowerOutcome(
        power_state=POWER_STOPPING,
        confirmed=False,
        waited_s=time.monotonic() - started,
        vmrun_error=precheck_error,
        detail=(
            "A graceful shutdown was requested; this call did not wait "
            "(waited_s is issue time, not shutdown time). Check vm_status: "
            "'stopped' means done. Still running minutes later? mode='hard' "
            "is the deliberate follow-up; this tool's description carries "
            "the full contract."
        ),
    )


async def _reap_background_stop(
    process: "asyncio.subprocess.Process",
    args: list[str],
) -> None:
    """Own a fire-and-forget graceful stop once the tool call has returned.

    Nobody is awaiting this process, but it must not be abandoned: its stdout
    and stderr pipes need draining (a full pipe buffer can wedge a child on
    Windows), and the outcome is worth a log line because it is not observable
    in any result the caller received. On `SOFT_STOP_CEILING` the process is
    killed -- a stop that outlives it is the guest refusing shutdown, which
    the agent discovers through vm_status and answers with `hard` if it wants.
    """
    vmx = args[1]
    try:
        result = await _collect(process, args, SOFT_STOP_CEILING)
    except VmrunUnavailable as exc:
        logger.warning("background graceful stop for %s lost contact: %s", vmx, exc)
        return

    if result.ok:
        logger.info("background graceful stop for %s finished (exit 0)", vmx)
    else:
        logger.warning(
            "background graceful stop for %s exited %s: %s",
            vmx,
            result.exit_code,
            _describe(result),
        )


async def _stop_hard(
    vmx_path: str | Path, *, executable: Path | None = None
) -> VmrunResult:
    """`vmrun stop <vmx> hard`, which returns as soon as power is cut (~1s)."""
    return await run_vmrun(
        ["stop", str(vmx_path), STOP_HARD],
        timeout=STOP_HARD_TIMEOUT,
        executable=executable,
    )


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