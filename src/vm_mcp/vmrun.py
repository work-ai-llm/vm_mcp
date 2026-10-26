"""Subprocess wrapper for VMware Workstation's `vmrun`.

vmrun is the only supported way to ask VMware Workstation about VM power state.
This module exists because the raw command line is a trap in four specific ways,
each of which cost or would have cost a debugging cycle:

1. **Error messages go to stdout, not stderr, and the exit code is -1.**
   A nonexistent `.vmx` returns exit -1 and prints `Error: Cannot open VM: ...`
   on *stdout*. Code that reads only stderr sees nothing and treats the error
   output as data. Both streams are captured and merged here so that cannot
   happen at the call site.

2. **The console codepage mangles native-language output.** This host runs a
   cp866 console. Output is read as bytes and decoded as UTF-8 with replacement,
   never handed to Python's text-mode decoding of a cp866 stream.

3. **A shell would interpret VM names.** vmrun is invoked as an argument vector
   through `create_subprocess_exec`, so a VM named `a & b` is one argument, not
   a command injection.

4. **Only the running set is exposed by `list`.** `vmrun list` answers "which
   VMs are running right now", not "which VMs exist". Enumerating the full set
   is `roster.py`'s job. This module never pretends `list` is an inventory.

Every call is bounded by a timeout. A hung vmrun is a hung tool call, and a
tool call that never returns is worse than one that fails.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "VMRUN_PATH",
    "STOP_HARD",
    "STOP_SOFT",
    "VmrunResult",
    "VmrunUnavailable",
    "run_vmrun",
    "spawn_vmrun",
    "list_running_vmx",
    "power_on",
    "tools_state",
    "get_guest_ip",
    "parse_list_output",
    "normalize_uuid",
]

logger = logging.getLogger(__name__)

# Verified present on the M0 host. Overridable per-call via run_vmrun(executable=)
# so tests never have to depend on this path.
# Can be overridden via VMWARE_VMRUN_PATH environment variable.
VMRUN_PATH = Path(
    os.environ.get("VMWARE_VMRUN_PATH", r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")
)

# Timeouts are per-command and generous. `list` measured 0.55s and
# `checkToolsState` 0.65-3.5s on a cold, heavily loaded machine; these ceilings
# are for a genuinely hung process, not for slow success.
DEFAULT_TIMEOUT = 20.0
LIST_TIMEOUT = 15.0

# Power-on returns as soon as the VM is powered on; measured 1.8s cold and 3.1s
# on this host, with outliers up to 3.4s. `nogui` keeps the command non-blocking
# and means no VMware window appears for a machine nobody is watching.
START_TIMEOUT = 60.0

# `stop ... hard` is measured at 0.9-1.2s and waits for nothing. `stop ... soft`
# is a *different animal entirely* and was verified rather than assumed:
#
#     vmrun -T ws stop "<VMX>" soft   ->  exit 0 after 26.3s
#
# It does not return when the request is delivered, it returns when the guest
# has actually shut down -- which is the correct behaviour for a graceful stop,
# and the reason the two modes need different timeouts rather than one shared
# "stop" constant. A generous ceiling covers a Windows domain controller draining
# Active Directory; exceeding it is not automatically an error, so callers that
# care should poll `list` instead of trusting this timeout alone.
STOP_HARD_TIMEOUT = 60.0
STOP_SOFT_TIMEOUT = 900.0

STOP_SOFT = "soft"
STOP_HARD = "hard"


class VmrunUnavailable(RuntimeError):
    """vmrun could not be executed, exited non-zero, or timed out.

    This is distinct from "the command succeeded and said nothing interesting".
    Callers must not treat it as a negative answer -- a host fault would
    otherwise be reported as "every VM is powered off", which is a confident
    wrong answer to the exact question the model asked.
    """


@dataclass(frozen=True)
class VmrunResult:
    """Outcome of one vmrun invocation.

    Attributes:
        ok: True only if vmran ran and exited zero.
        stdout: Decoded stdout, with stderr appended if it produced anything.
        exit_code: Process exit code. vmrun uses -1 for its own errors.
    """

    ok: bool
    stdout: str
    exit_code: int


async def _collect(process: "asyncio.subprocess.Process", args: list[str], timeout: float) -> VmrunResult:
    """Wait for a spawned vmrun, bounded, and decode its merged output."""
    try:
        raw_out, raw_err = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError as exc:
        # A hung vmrun would otherwise hold the tool call open indefinitely.
        try:
            process.kill()
            await process.wait()
        except ProcessLookupError:
            pass
        raise VmrunUnavailable(
            f"vmrun {args[0] if args else '?'} timed out after {timeout}s"
        ) from exc

    # See note 1: vmrun reports its own errors on stdout with exit -1. Merging
    # means the caller can pattern-match "Error:" without having to know that.
    text = raw_out.decode("utf-8", "replace").strip()
    err_text = raw_err.decode("utf-8", "replace").strip()
    if err_text:
        text = f"{text}\n{err_text}" if text else err_text

    exit_code = process.returncode if process.returncode is not None else -1
    return VmrunResult(ok=exit_code == 0, stdout=text, exit_code=exit_code)


async def spawn_vmrun(
    args: list[str],
    *,
    executable: Path | None = None,
) -> "asyncio.subprocess.Process":
    """Start `vmrun -T ws <args>` and hand back the live process.

    The only reason this exists, and the reason it is not the default path: a
    graceful `stop` **blocks until the guest has finished shutting down**
    (measured 26.3s for the Ubuntu jumpbox), and the caller enforces a fixed
    request timeout that such a wait can outlive by minutes. Awaiting it would
    spends the caller's budget waiting on the guest instead of answering, so
    the command is started, handed to a background owner (`power.py` reaps
    it), and the caller is answered at once.

    The caller owns the process and is responsible for consuming it (via
    `_collect`, or by killing it). Nothing here enforces that.

    Raises:
        VmrunUnavailable: vmrun is missing or could not be started.
    """
    binary = Path(executable) if executable is not None else VMRUN_PATH

    if not binary.is_file():
        raise VmrunUnavailable(f"vmrun not found at {binary}")

    # -T ws pins the target to the local Workstation instance. Without it
    # vmrun probes for vix servers and can stall on a network lookup.
    command = [str(binary), "-T", "ws", *args]

    try:
        return await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        raise VmrunUnavailable(f"could not start vmrun: {exc}") from exc


async def run_vmrun(
    args: list[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    executable: Path | None = None,
) -> VmrunResult:
    """Run `vmrun -T ws <args>` and return its output.

    Args:
        args: Subcommand and its arguments, e.g. `["list"]`.
        timeout: Seconds before the process is killed.
        executable: Override the vmrun binary path. Tests use this.

    Returns:
        A VmrunResult. `ok` is False if the exit code was non-zero.

    Raises:
        VmrunUnavailable: vmrun is missing, could not be started, or timed out.
    """
    process = await spawn_vmrun(args, executable=executable)
    return await _collect(process, args, timeout)


def parse_list_output(stdout: str) -> list[str]:
    """Extract the VMX paths from `vmrun list` output.

    The format, verified against a real 3-VM run, is exactly:

        Total running VMs: 3
        D:\\path\\to\\one.vmx
        D:\\path\\to\\two.vmx
        D:\\path\\to\\three.vmx

    CRLF line endings; no trailing blank line. The header is parsed but its
    count is not trusted as the length -- the returned list is built from the
    paths actually present, so a truncated response cannot inflate or deflate
    the count the caller reports.

    Args:
        stdout: Raw decoded stdout from `vmrun list`.

    Returns:
        VMX paths in the order vmrun reported them. Empty if none are running
        or the output is not in the expected shape.
    """
    lines = [line.strip() for line in stdout.splitlines()]
    paths: list[str] = []

    for line in lines:
        if not line:
            continue
        if re.match(r"^Total running VMs:", line, re.IGNORECASE):
            continue
        # vmrun reports its own errors as `Error: Cannot open VM: <path>.vmx`.
        # That line ends in `.vmx` like a real path does, so the suffix test
        # below would happily accept it and hand back a path that does not
        # exist as though it were a running VM. Errors are rejected first.
        if re.match(r"^(Error|Unable to|Warning):", line, re.IGNORECASE):
            continue
        # A path line. Ends in `.vmx`; anything else is not a path and is
        # dropped rather than passed off as one. Checked with a suffix test
        # rather than a regex because a dotted regex like `\\.vmx` would
        # require a backslash immediately before the extension, which no .vmx
        # path has -- it silently matches nothing.
        if line.lower().endswith(".vmx"):
            paths.append(line)

    return paths


async def list_running_vmx(
    *, timeout: float = LIST_TIMEOUT, executable: Path | None = None
) -> list[str]:
    """Return the `.vmx` paths of VMs currently running.

    Raises:
        VmrunUnavailable: vmrun failed or timed out. Never returns an empty list
            to mean "unavailable" -- the caller must distinguish host fault from
            an empty lab, and only the exception carries that distinction.
    """
    result = await run_vmrun(["list"], timeout=timeout, executable=executable)

    # Log raw output at debug level. If a future VMware release changes the
    # format, this is what makes it diagnosable without a debugger.
    logger.debug("vmrun list exit=%s raw=%r", result.exit_code, result.stdout)

    if not result.ok:
        raise VmrunUnavailable(f"vmrun list failed (exit {result.exit_code})")

    if re.search(r"^Error:", result.stdout, re.MULTILINE | re.IGNORECASE):
        raise VmrunUnavailable("vmrun list reported an error")

    return parse_list_output(result.stdout)


async def power_on(
    vmx_path: str | Path,
    *,
    timeout: float = START_TIMEOUT,
    executable: Path | None = None,
) -> VmrunResult:
    """Power on a VM without a console window.

    Issues `vmrun start <vmx> nogui`.

    Two things about the return value that are easy to get wrong:

    * **`nogui` is what makes this usable.** Without it VMware opens a window for
      a machine nobody is sitting in front of.
    * **This returning means "power-on accepted", not "guest usable".** Measured
      on this host: `start` exits 0 after 1.8s cold / 3.1s warm, and the guest
      does not become reachable for a further **~156s**. A caller that reads exit
      zero as "the VM is up and working" is wrong for two and a half minutes.

    Raises:
        VmrunUnavailable: vmrun failed, timed out, or rejected the path.
    """
    return await run_vmrun(
        ["start", str(vmx_path), "nogui"],
        timeout=timeout,
        executable=executable,
    )


async def tools_state(
    vmx_path: str | Path,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    executable: Path | None = None,
) -> str:
    """Return VMware Tools state for one VM: 'installed', 'running', or ''.

    VMware Tools is the agent installed *inside* the guest OS. This reports
    whether that agent is present in the VM's files and whether its service is
    currently active, which is only meaningful while the guest is running.

    Args:
        vmx_path: Absolute path to the VM's `.vmx` file.

    Raises:
        VmrunUnavailable: vmrun failed, timed out, or rejected the path.
    """
    result = await run_vmrun(
        ["checkToolsState", str(vmx_path)],
        timeout=timeout,
        executable=executable,
    )

    if not result.ok:
        raise VmrunUnavailable(
            f"checkToolsState failed (exit {result.exit_code})"
        )

    # Observed values are exactly 'installed' or 'running'. Anything else is
    # passed through rather than guessed at, so an unexpected value shows up in
    # the tool result instead of being silently normalised to a wrong one.
    return result.stdout.strip().lower()


async def get_guest_ip(
    vmx_path: str | Path,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    executable: Path | None = None,
) -> str | None:
    """Return the guest's own reported IP address, or None when it has none.

    This is `getGuestIPAddress`, which needs VMware Tools running in the guest.
    The answer is *unvalidated*: it reports one address of several, and on this
    lab it has been observed returning an address the host cannot route to on
    one VM and the host-reachable one on another (research blocker B2). This
    function returns it and nothing more; reachability checking and the probe
    live in `health.py`, so the tool's result can say where each address came
    from and which ones were thrown away.

    Args:
        vmx_path: Absolute path to the VM's `.vmx` file.

    Returns:
        The IP string, or None when vmrun declined to answer (guest powered
        off, Tools not running, or no address acquired yet). A decline is the
        guest's problem, not the host's.

    Raises:
        VmrunUnavailable: vmrun failed or timed out, which is a host fault and
            must stay distinguishable from "this guest has no address".
    """
    result = await run_vmrun(
        ["getGuestIPAddress", str(vmx_path)], timeout=timeout, executable=executable
    )
    if not result.ok:
        return None
    text = result.stdout.strip()
    return text or None


def normalize_uuid(value: str) -> str:
    """Normalize a UUID for comparison.

    Two formats appear in practice: the registry writes `56 4d f4 8b bf be 94
    a5-f8 b5 17 60 df 89 9e 33` with spaces, while a caller may pass it without
    spaces, or in dashed form. Case is not significant.

    Returns:
        Lowercase hex digits only, with every separator removed.
    """
    return re.sub(r"[^0-9a-f]", "", value.lower())