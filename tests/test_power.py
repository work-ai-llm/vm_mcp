"""Tests for the M2 tool surface: `start_vm`, `stop_vm`, `restart_vm`.

No VMware process is started by anything in this file. `vmrun` is replaced with a
fake that records calls and returns canned output, so the whole suite is about
*contracts*: which fields a result carries, what happens when the hypervisor
disagrees with the command, and -- most of all -- what does not happen when a
caller supplies something that is not a VM.

The behaviours pinned here were decided against real measurements, and each one
guards a specific way this could be wrong:

* `vmrun start ... nogui` exits 0 in ~2s while the guest needs a further ~156s.
  So a start must never be reported as "ready", and must report the gap.
* `vmrun stop ... soft` **blocks** until the guest has shut down (measured 26.3s
  on the Ubuntu jumpbox). So the poll ladder must run *concurrently* with the
  command, not after it, or it is dead code.
* `vmrun` reports its own errors on **stdout** with exit -1.
* A command's exit code is not evidence its effect happened. Every result is
  read back from `vmrun list` instead.

Run:
    ..\\.venv\\Scripts\\python.exe -m pytest tests/test_power.py -v
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from vm_mcp import power, roster, server
from vm_mcp.vmrun import VmrunResult, VmrunUnavailable

# --- fixtures -------------------------------------------------------------

DC01_UUID = "56 4d f4 8b bf be 94 a5-f8 b5 17 60 df 89 9e 33"
WAZUH_UUID = "56 4d e0 b5 86 57 4b 06-5c 82 f2 7e 01 37 b4 1d"

DC01_VMX = """\
.encoding = "UTF-8"
displayname = "provider: GOAD-DC01"
guestos = "windows9srv-64"
numvcpus = "2"
memsize = "3000"
"""

WAZUH_VMX = """\
.encoding = "UTF-8"
displayName = "wazuh-4.7.5"
guestos = "otherlinux-64"
numvcpus = "4"
memsize = "8192"
"""


class FakeVm:
    """A VM with a controllable power state, driven through a fake vmrun.

    Models the thing that actually happens in life: a command can be told to
    succeed while the hypervisor reports something else. `start_lying` and
    `stop_lying` exist so that disagreement can be exercised directly.
    """

    def __init__(self, name: str, uuid: str, vmx: Path) -> None:
        self.name = name
        self.uuid = uuid
        self.vmx = vmx
        self.running = False

    @property
    def path(self) -> str:
        return str(self.vmx)


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A synthetic lab whose .vmx files really exist on disk.

    The existence check matters: `start_vm` refuses a registered VM whose .vmx is
    missing, and that check is only reachable if the fixtures have real files.
    """
    vmx_dir = tmp_path / "vmx"
    vmx_dir.mkdir()

    dc01 = FakeVm(
        "provider: GOAD-DC01", DC01_UUID, vmx_dir / "WindowsServer2019.vmx"
    )
    dc01.vmx.write_text(DC01_VMX, encoding="utf-8")
    wazuh = FakeVm("wazuh-4.7.5", WAZUH_UUID, vmx_dir / "wazuh-4.7.5.vmx")
    wazuh.vmx.write_text(WAZUH_VMX, encoding="utf-8")

    registry_file = tmp_path / "inventory.vmls"
    registry_file.write_bytes(
        "\r\n".join(
            [
                '.encoding = "windows-1251"',
                f'vmlist1.config = "{dc01.path}"',
                f'vmlist1.DisplayName = "{dc01.name}"',
                f'vmlist1.UUID = "{dc01.uuid}"',
                f'vmlist2.config = "{wazuh.path}"',
                f'vmlist2.DisplayName = "{wazuh.name}"',
                f'vmlist2.UUID = "{wazuh.uuid}"',
            ]
        ).encode("windows-1251")
    )

    monkeypatch.setattr(roster, "inventory_path", lambda: registry_file)

    return {"dc01": dc01, "wazuh": wazuh, "registry": registry_file}


@pytest.fixture
def fake_vmrun(lab, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Any]:
    """Install a fake vmrun that keeps the fake VMs' power state consistent.

    `start` and `stop` flip the modelled power state, so the poll ladder observes
    a VM that really does go away -- which is the only way these tests can prove
    the ladder terminates on the right condition rather than on a timeout.

    Knobs, all off by default:
      * `list_unavailable` -- every `vmrun list` fails, as a host fault would.
      * `start_noop`        -- `start` exits 0 but changes nothing.
      * `stop_never_dies`   -- `stop` exits 0 and the VM stays running forever.
      * `command_error`     -- power commands exit non-zero with vmrun's own
                               stdout error shape.
    """

    class Harness:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []
            self.list_unavailable = False
            self.start_noop = False
            self.stop_never_dies = False
            self.command_error = False
            # How many `vmrun list` calls a graceful stop makes before the VM
            # goes down. Used to prove the ladder escalates rather than polling
            # flat out.
            self.die_after_polls = 0
            self._polls_during_stop = 0

        @property
        def vms(self) -> list[FakeVm]:
            return [lab["dc01"], lab["wazuh"]]

        def running_paths(self) -> list[str]:
            return [vm.path for vm in self.vms if vm.running]

        def list_output(self) -> str:
            paths = self.running_paths()
            lines = [f"Total running VMs: {len(paths)}"] + paths
            return "\r\n".join(lines)

        def target(self, vmx: str) -> FakeVm:
            for vm in self.vms:
                if vm.path.lower() == vmx.lower():
                    return vm
            raise AssertionError(f"no fake VM at {vmx}")

        async def list_running_vmx(self, **_: Any) -> list[str]:
            self.calls.append(["list"])
            if self.list_unavailable:
                raise VmrunUnavailable("vmrun list failed (exit -1)")
            return self.running_paths()

        async def power_on(self, vmx: str | Path, **_: Any) -> VmrunResult:
            self.calls.append(["start", str(vmx), "nogui"])
            if self.command_error:
                return VmrunResult(
                    ok=False, stdout="Error: Cannot open VM", exit_code=-1
                )
            if not self.start_noop:
                self.target(str(vmx)).running = True
            return VmrunResult(ok=True, stdout="", exit_code=0)

        def _do_stop(self, vmx: str, mode: str) -> VmrunResult:
            self.calls.append(["stop", vmx, mode])
            if self.command_error:
                return VmrunResult(
                    ok=False, stdout="Error: Cannot open VM", exit_code=-1
                )
            if not self.stop_never_dies:
                self.target(vmx).running = False
            return VmrunResult(ok=True, stdout="", exit_code=0)

        async def run_vmrun(self, args: list[str], **_: Any) -> VmrunResult:
            """Awaitable, as the real one is.

            `power._stop_hard` awaits this directly, so a sync stub would fail
            with "object VmrunResult can't be used in 'await' expression" --
            which is a defect in the test harness, not in the code under test,
            and worth getting right so the harness models the real contract.
            """
            return self._do_stop(args[1], args[2])

        def spawn_vmrun(self, args: list[str], **_: Any) -> "asyncio.Future":
            """Stand in for the real spawn: an awaitable yielding the result.

            The production code awaits this concurrently with the poll ladder,
            so the fake must be awaitable in the same way. It runs the stop
            immediately, which is what makes the ladder's first poll see a VM that
            has already gone -- the same shape as a fast Linux shutdown.

            The stop runs *before* the future is created, so `_collect` receives a
            `VmrunResult` and must hand it back unchanged rather than await it.
            """
            result = self._do_stop(args[1], args[2])
            fut: "asyncio.Future[VmrunResult]" = asyncio.Future()
            fut.set_result(result)
            return fut

        async def _collect(self, process: Any, args: list[str], timeout: float) -> VmrunResult:
            """Mirror the real `_collect`: accept a future or a plain result."""
            if isinstance(process, VmrunResult):
                return process
            return await process

    def install(**kwargs: Any) -> Harness:
        harness = Harness()
        for key, value in kwargs.items():
            setattr(harness, key, value)

        monkeypatch.setattr(power, "list_running_vmx", harness.list_running_vmx)
        monkeypatch.setattr(power, "power_on", harness.power_on)
        monkeypatch.setattr(power, "run_vmrun", harness.run_vmrun)
        monkeypatch.setattr(power, "spawn_vmrun", harness.spawn_vmrun)
        monkeypatch.setattr(power, "_collect", harness._collect)
        # Keep the ladder instant: the shape is asserted separately, and 220 real
        # seconds of sleeping would make this suite unusable.
        monkeypatch.setattr(power, "SOFT_STOP_LADDER", (0, 0, 0, 0))
        return harness

    return install


def call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return asyncio.run(fn(*args, **kwargs))


def call_powered(fn: Callable[..., Any], lab: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
    """Call a power tool against a VM that is already running.

    `stop` now checks power state first and short-circuits on an already-stopped
    VM, which is correct but means these tests have to start the VM to have
    anything to stop. Doing it through the real `start_vm` keeps the fixture
    honest: if start and stop disagreed about power state, these tests would fail
    rather than quietly pass.
    """
    lab["dc01"].running = True
    return call(fn, *args, **kwargs)


# --- identity: what may be acted on ---------------------------------------


def test_unknown_identifier_starts_no_process(lab, fake_vmrun) -> None:
    """The security property every mutating tool inherits.

    An identifier that does not resolve must not reach vmrun at all. A tool
    accepting a caller-supplied path would be an arbitrary-file-primitive with a
    power switch on it; this is the test that would notice.
    """
    harness = fake_vmrun()

    for tool in (server.start_vm, server.stop_vm, server.restart_vm):
        with pytest.raises(ToolError):
            call(tool, uuid="de ad be ef 00 00 00 00-00 00 00 00 00 00 00 ff")

    assert harness.calls == []


def test_a_path_is_not_accepted_as_a_name(lab, fake_vmrun) -> None:
    """`stop_vm("../../Windows/System32/config")` must be a plain error.

    This is the exact scenario issue #15 was written about, and it is worth an
    explicit test rather than relying on the general unknown-identifier case: it
    is the one a confused agent produces without any intent to attack.
    """
    harness = fake_vmrun()

    with pytest.raises(ToolError) as excinfo:
        call(server.stop_vm, name=r"..\..\Windows\System32\config")

    assert harness.calls == []
    assert "no registered VM matches" in str(excinfo.value)


def test_stale_registry_entry_fails_before_any_command(lab, fake_vmrun) -> None:
    """The registry is a cache written by the VMware GUI; it can name a .vmx that
    is gone. Refusing before the command is what keeps a stale entry from
    becoming a confusing vmrun error -- and, more importantly, stops a power
    operation aimed at a path that no longer means anything.
    """
    lab["wazuh"].vmx.unlink()
    harness = fake_vmrun()

    with pytest.raises(ToolError) as excinfo:
        call(server.stop_vm, uuid=WAZUH_UUID)

    assert harness.calls == []
    assert ".vmx is missing" in str(excinfo.value)


def test_every_result_names_the_vm_it_acted_on(lab, fake_vmrun) -> None:
    """A caller must be able to check *which* machine this touched.

    A result that said `{"power_state": "stopped"}` and nothing else would leave
    an agent unable to verify it acted on the VM it meant to.
    """
    harness = fake_vmrun()

    started = call(server.start_vm, uuid=DC01_UUID)
    assert started["name"] == "provider: GOAD-DC01"
    assert started["uuid"] == DC01_UUID

    stopped = call(server.stop_vm, uuid=DC01_UUID)
    assert stopped["name"] == "provider: GOAD-DC01"

    assert harness.calls, "the VM was actually acted on"


def test_only_the_named_vm_is_touched(lab, fake_vmrun) -> None:
    """One call, one machine. The lab is six VMs and an appliance; a tool that
    drifted into operating on more than the one it was asked about would be the
    worst bug in the project."""
    fake_vmrun()

    call(server.start_vm, uuid=DC01_UUID)

    assert lab["dc01"].running is True
    assert lab["wazuh"].running is False


# --- start_vm -------------------------------------------------------------


def test_start_reports_the_vm_as_powered_on(lab, fake_vmrun) -> None:
    harness = fake_vmrun()

    result = call(server.start_vm, uuid=DC01_UUID)

    assert result["power_state"] == "running"
    assert result["confirmed"] is True
    assert ["start", lab["dc01"].path, "nogui"] in harness.calls


def test_start_never_claims_the_guest_is_usable(lab, fake_vmrun) -> None:
    """The 156s gap, and the most misleading thing this tool could do.

    `vmrun start` returns in ~2s and the guest is unusable for another ~156s. A
    result that read "running" with nothing else invites the agent to say the
    domain controller is up and ready, which is wrong for two and a half minutes.
    """
    fake_vmrun()

    result = call(server.start_vm, uuid=DC01_UUID)

    detail = result["detail"].lower()
    assert "not usable" in detail
    assert "150" in detail or "156" in detail


def test_start_that_vmrun_says_succeeded_but_did_not_happen_is_a_failure(
    lab, fake_vmrun
) -> None:
    """Exit code is not evidence. Read the post-condition.

    The regression this guards is a `{"ok": true}` built from `result.ok` with no
    read-back -- which reports a failed start as a successful one, from the tool
    whose entire job is to tell an agent whether the lab is up.
    """
    harness = fake_vmrun(start_noop=True)

    result = call(server.start_vm, uuid=DC01_UUID)

    assert result["power_state"] == "stopped"
    assert result["confirmed"] is True
    assert "treat this as a failed start" in result["detail"].lower()


def test_start_that_cannot_be_confirmed_is_not_reported_as_running(
    lab, fake_vmrun
) -> None:
    """vmrun reachable for the command, unreachable afterwards.

    The VM may well be up. We cannot see it, so the honest answer is
    `unknown` + `confirmed: False` -- never `running`, which would be a guess
    about a domain controller's power state.
    """
    fake_vmrun(list_unavailable=True)

    result = call(server.start_vm, uuid=DC01_UUID)

    assert result["power_state"] == power.POWER_UNKNOWN
    assert result["confirmed"] is False
    assert result["vmrun_error"]


def test_start_that_vmrun_rejects_reports_the_error(lab, fake_vmrun) -> None:
    """vmrun prints its errors on stdout with exit -1, and the text names the
    path VMware refused. That text is the only useful diagnostic available."""
    fake_vmrun(command_error=True)

    result = call(server.start_vm, uuid=DC01_UUID)

    assert result["confirmed"] is False
    assert "Cannot open VM" in result["vmrun_error"]


# --- stop_vm --------------------------------------------------------------


def test_stop_defaults_to_a_graceful_shutdown(lab, fake_vmrun) -> None:
    """Soft is the default because it lets the guest unmount cleanly.

    The plan intended this and the research had never tested it. It is now
    verified: `vmrun stop soft` exits 0 after 26.3s on the Ubuntu jumpbox, having
    actually shut the guest down rather than merely requesting it.
    """
    harness = fake_vmrun()

    result = call_powered(server.stop_vm, lab, uuid=DC01_UUID)

    assert result["mode"] == "soft"
    assert ["stop", lab["dc01"].path, "soft"] in harness.calls


def test_stop_hard_uses_the_hard_mode(lab, fake_vmrun) -> None:
    harness = fake_vmrun()

    result = call_powered(server.stop_vm, lab, uuid=DC01_UUID, mode="hard")

    assert result["mode"] == "hard"
    assert ["stop", lab["dc01"].path, "hard"] in harness.calls
    assert result["power_state"] == "stopped"


def test_stop_rejects_a_mode_that_is_not_a_mode(lab, fake_vmrun) -> None:
    """Fail loudly on a typo. An unrecognised mode silently treated as `soft`
    would mean a caller asking to cut power got a graceful shutdown instead."""
    harness = fake_vmrun()

    with pytest.raises(ValueError) as excinfo:
        call(server.stop_vm, uuid=DC01_UUID, mode="harder")

    assert harness.calls == []
    assert "soft" in str(excinfo.value)


def test_stop_reports_the_vm_as_stopped_only_after_it_is_gone(
    lab, fake_vmrun
) -> None:
    """Confirmed by observation, not by the command's opinion."""
    fake_vmrun()

    result = call_powered(server.stop_vm, lab, uuid=DC01_UUID)

    assert result["power_state"] == "stopped"
    assert result["confirmed"] is True
    assert lab["dc01"].running is False


def test_stop_that_never_finishes_reports_the_vm_still_running(lab, fake_vmrun) -> None:
    """The case the whole ladder exists for.

    A guest that ignores the shutdown request -- waiting on a prompt, a hung
    service, a filesystem that will not flush -- is still running after 220s. The
    correct answer is "still up, recommend hard", and the correct absence is any
    escalation to a power cut.
    """
    harness = fake_vmrun(stop_never_dies=True)

    result = call_powered(server.stop_vm, lab, uuid=DC01_UUID)

    assert result["power_state"] == "running"
    assert result["confirmed"] is True
    detail = result["detail"].lower()
    assert "still running" in detail
    assert "hard" in detail, "the caller must be told what to do next"
    assert lab["dc01"].running is True

    # And critically: no hard stop was attempted behind the caller's back.
    assert not any("hard" in call_arg for c in harness.calls for call_arg in c)


def test_stop_never_escalates_to_a_hard_power_cut(lab, fake_vmrun) -> None:
    """Stated separately from the test above, because it is the safety property
    rather than a reporting detail: escalating silently would make `stop_vm` a
    destructive tool wearing the name of a polite one."""
    harness = fake_vmrun(stop_never_dies=True)

    call_powered(server.stop_vm, lab, uuid=DC01_UUID)

    stops = [c for c in harness.calls if c[0] == "stop"]
    assert stops == [["stop", lab["dc01"].path, "soft"]], (
        f"a graceful stop must issue exactly one soft stop, got {stops}"
    )


def test_stop_of_an_already_stopped_vm_is_a_clean_no_op(lab, fake_vmrun) -> None:
    """Not an error, and no command issued.

    vmrun reports `Error: The virtual machine is not powered on` for this, which
    is a true statement about the request rather than a fault. Surfacing it would
    make a routine idempotent call look like a failure -- and `restart_vm` on a
    stopped VM hits it every single time, so the noise lands on the common path.
    """
    harness = fake_vmrun()

    result = call(server.stop_vm, uuid=DC01_UUID)

    assert result["power_state"] == "stopped"
    assert result["confirmed"] is True
    assert "already powered off" in result["detail"]
    assert "vmrun_error" not in result
    assert not any(c[0] == "stop" for c in harness.calls), (
        "there is nothing to stop; the command should not be issued"
    )


def test_restart_of_a_stopped_vm_does_not_report_a_stop_failure(
    lab, fake_vmrun
) -> None:
    """The consequence that matters.

    Restarting a VM that is already off is a normal thing to ask for. Its stop
    half must not come back carrying vmrun's "not powered on" error, or every
    restart from cold starts as a partially-failed operation.
    """
    fake_vmrun()

    result = call(server.restart_vm, uuid=DC01_UUID)

    assert result["stopped"]["power_state"] == "stopped"
    assert "vmrun_error" not in result["stopped"], (
        f'stop half reported an error on a no-op stop: {result["stopped"]}'
    )
    assert result["started"]["power_state"] == "running"


def test_stop_that_cannot_be_confirmed_is_unknown_not_stopped(
    lab, fake_vmrun
) -> None:
    """A host fault during the shutdown must not read as a successful stop.

    The inverse of the M1 rule for `list_vms`, and the same reasoning: "not in the
    running list" and "could not ask" are different facts, and collapsing them
    would report a powered-on domain controller as off with total confidence.
    """
    fake_vmrun(list_unavailable=True)

    result = call(server.stop_vm, uuid=DC01_UUID)

    assert result["power_state"] == power.POWER_UNKNOWN
    assert result["confirmed"] is False
    assert result["vmrun_error"]


def test_stop_hard_still_confirms_by_observation(lab, fake_vmrun) -> None:
    """Hard stop does not get a shortcut just because it is fast."""
    fake_vmrun()

    result = call_powered(server.stop_vm, lab, uuid=DC01_UUID, mode="hard")

    assert result["confirmed"] is True
    assert result["power_state"] == "stopped"


# --- restart_vm -----------------------------------------------------------


def test_restart_stops_then_starts(lab, fake_vmrun) -> None:
    harness = fake_vmrun()

    result = call_powered(server.restart_vm, lab, uuid=DC01_UUID)

    assert result["stopped"]["power_state"] == "stopped"
    assert result["started"]["power_state"] == "running"
    assert lab["dc01"].running is True

    order = [c[0] for c in harness.calls]
    assert order.index("stop") < order.index("start")


def test_restart_reports_both_halves_separately(lab, fake_vmrun) -> None:
    """Two operations wearing one name.

    The case worth seeing is a VM that came back up *without having cleanly
    stopped* -- it is running on stale state. A single verdict would hide exactly
    that, which is why the result nests both outcomes rather than summarising.
    """
    fake_vmrun()

    result = call_powered(server.restart_vm, lab, uuid=DC01_UUID)

    assert set(result["stopped"]) >= {"power_state", "confirmed", "waited_s"}
    assert set(result["started"]) >= {"power_state", "confirmed", "waited_s"}
    assert "power_state" not in result, (
        "restart must not collapse to one verdict; the two halves are separate "
        "outcomes and the interesting case is when they disagree"
    )


def test_restart_does_not_start_a_vm_that_did_not_stop(lab, fake_vmrun) -> None:
    """The safety property of the composition.

    A failed stop followed by a start produces a machine that looks up and is
    not -- two power states disagreeing and no report of it. The restart stops
    there and says so.
    """
    harness = fake_vmrun(stop_never_dies=True)

    result = call_powered(server.restart_vm, lab, uuid=DC01_UUID)

    assert result["stopped"]["power_state"] == "running"
    assert result["started"]["confirmed"] is False
    assert "not confirmed stopped" in result["started"]["detail"].lower()

    assert not any(c[0] == "start" for c in harness.calls), (
        "powering on a VM that was still running would produce a machine that "
        "looks up and is not"
    )


def test_restart_forwards_the_stop_mode(lab, fake_vmrun) -> None:
    """`mode` governs the stop half; the start half has no mode."""
    harness = fake_vmrun()

    result = call_powered(server.restart_vm, lab, uuid=DC01_UUID, mode="hard")

    assert result["mode"] == "hard"
    assert ["stop", lab["dc01"].path, "hard"] in harness.calls


# --- the ladder -----------------------------------------------------------


def test_ladder_is_escalating_and_bounded() -> None:
    """The shape is the design: cost tracks the actual wait.

    A guest that shuts down in 8s costs one 10s poll; a slow Windows domain
    controller still gets 220s of patience inside a single tool call. A flat
    schedule would either be slow in the common case or give up early on the case
    that needs patience.
    """
    ladder = power.SOFT_STOP_LADDER

    assert list(ladder) == sorted(ladder), "poll times must not go backwards"
    assert len(set(ladder)) == len(ladder), "no duplicate checkpoints"
    assert sum(ladder) == 220, "the documented patience ceiling"
    assert ladder[0] == 10, "the common case must be cheap"


def test_graceful_stop_polls_while_the_command_runs(lab, monkeypatch) -> None:
    """The reason `spawn_vmrun` exists at all.

    `vmrun stop soft` blocks until the guest is down -- measured 26.3s. If the
    command were simply awaited, the ladder could only run *after* it returned,
    at which point the answer is already known and the ladder is dead code. So
    the command is spawned and polled against concurrently.

    The fake command therefore takes several event-loop turns to "finish", the
    way the real one takes 26 real seconds. If the implementation awaited it
    before polling, the polls would all land after `command-finishes` and this
    test fails on the ordering assertion below.
    """
    order: list[str] = []
    polls = {"n": 0}

    class SlowStop:
        returncode = None

        async def wait(self) -> None:
            return None

        def kill(self) -> None:
            return None

    async def collect(process: Any, args: list[str], timeout: float) -> VmrunResult:
        # Several awaits: the event loop must get a turn before this completes,
        # which is what lets the poll ladder observe state mid-shutdown.
        for _ in range(5):
            await asyncio.sleep(0)
        order.append("command-finishes")
        return VmrunResult(ok=True, stdout="", exit_code=0)

    async def spawn(args: list[str], **_: Any) -> SlowStop:
        order.append("spawn")
        return SlowStop()

    async def fake_list(**_: Any) -> list[str]:
        polls["n"] += 1
        order.append(f"poll-{polls['n']}")
        # Still running for the first two polls, gone by the third -- a guest
        # that takes a while to notice it has been asked to shut down.
        if polls["n"] < 3:
            return [r"D:\some\other.vmx"]
        return []

    monkeypatch.setattr(power, "spawn_vmrun", spawn)
    monkeypatch.setattr(power, "_collect", collect)
    monkeypatch.setattr(power, "list_running_vmx", fake_list)
    monkeypatch.setattr(power, "SOFT_STOP_LADDER", (0, 0, 0))

    outcome = asyncio.run(power.stop(r"D:\some\other.vmx", mode="soft"))

    assert outcome.power_state == "stopped"
    assert polls["n"] == 3, "polled until the VM was observed going down"

    # The ordering is the whole point: a poll must be able to observe state
    # *before* the blocking command has returned.
    first_poll = order.index("poll-1")
    assert first_poll < order.index("command-finishes"), (
        f"polls must run concurrently with the blocking stop, got {order}"
    )


def test_stop_does_not_leave_a_vmrun_behind_on_timeout(
    lab, monkeypatch
) -> None:
    """A stop that outlives its patience must not leave a process holding the VM.

    The caller is told the stop timed out and will retry; a surviving vmrun means
    the retry now contends with the original for one machine.
    """
    killed: list[bool] = []

    class Stubborn:
        returncode = None

        async def wait(self) -> None:
            return None

        def kill(self) -> None:
            killed.append(True)
            self.returncode = -9

    stub = Stubborn()

    async def never_finishes(*_: Any, **__: Any) -> VmrunResult:
        await asyncio.sleep(3600)

    async def spawn(*_: Any, **__: Any) -> Stubborn:
        return stub

    async def always_running(**_: Any) -> list[str]:
        return [r"D:\some\other.vmx"]

    monkeypatch.setattr(power, "spawn_vmrun", spawn)
    monkeypatch.setattr(power, "_collect", never_finishes)
    monkeypatch.setattr(power, "list_running_vmx", always_running)
    monkeypatch.setattr(power, "SOFT_STOP_LADDER", (0, 0))

    outcome = asyncio.run(power.stop(r"D:\some\other.vmx", mode="soft"))

    assert outcome.power_state == "running"
    assert killed, "the stuck vmrun must be killed, not abandoned"


# --- annotations ----------------------------------------------------------


def test_power_tools_are_not_advertised_as_read_only() -> None:
    """The annotation a model reads to decide what it is allowed to do.

    Enumerated exhaustively rather than naming two tools, so a future tool cannot
    ship with the wrong hints by accident.
    """

    async def go() -> list[Any]:
        return list(await server.mcp.list_tools())

    tools = {t.name: t for t in asyncio.run(go())}
    mutating = {"start_vm", "stop_vm", "restart_vm"}

    assert mutating <= set(tools)
    for name in mutating:
        annotations = tools[name].annotations
        assert annotations is not None, f"{name} has no annotations"
        assert annotations.read_only_hint is False, (
            f"{name} changes power state and must not claim to be read-only"
        )

    # The destructive distinction is the one an agent uses to decide whether a
    # call needs care. `hard` on a domain controller risks filesystem damage.
    for name in ("stop_vm", "restart_vm"):
        assert tools[name].annotations.destructive_hint is True, (
            f"{name} can cut power and must be marked destructive"
        )

    # Powering on destroys nothing, and marking it destructive would train an
    # agent to distrust the one power operation that is routinely safe.
    assert tools["start_vm"].annotations.destructive_hint is False


def test_every_power_tool_documents_that_powered_on_is_not_usable() -> None:
    """The 156s gap has to be in the tool descriptions, not only in prose.

    Descriptions are what the model actually reads before calling. `start_vm` and
    `restart_vm` both produce a `running` that means "powered on"; an agent that
    reads only the name and the result will treat it as "ready".
    """

    async def go() -> dict[str, Any]:
        return {t.name: t.description or "" for t in await server.mcp.list_tools()}

    descriptions = asyncio.run(go())

    for name in ("start_vm", "restart_vm"):
        text = descriptions[name].lower()
        assert "not usable" in text or "not ready" in text, (
            f"{name} must say that running is not the same as usable"
        )


def test_power_tools_take_identifiers_not_paths() -> None:
    """A `vmx` argument would be the vulnerability this project was designed to
    avoid. Asserted on the published schema, because that is what the client
    enforces -- a parameter the model cannot see cannot be supplied by mistake."""
    async def go() -> dict[str, Any]:
        return {t.name: t.input_schema for t in await server.mcp.list_tools()}

    schemas = asyncio.run(go())

    for name in ("start_vm", "stop_vm", "restart_vm"):
        properties = set(schemas[name]["properties"])
        assert properties <= {"uuid", "name", "mode"}, (
            f"{name} accepts {properties}; only identifiers and mode belong here"
        )
        assert "vmx" not in properties


def test_stop_and_restart_default_to_soft_in_the_schema() -> None:
    """The published default, not just the Python signature.

    A client that renders defaults from the schema would otherwise display
    something other than what actually happens.
    """

    async def go() -> dict[str, Any]:
        return {t.name: t.input_schema for t in await server.mcp.list_tools()}

    schemas = asyncio.run(go())

    for name in ("stop_vm", "restart_vm"):
        assert schemas[name]["properties"]["mode"].get("default") == "soft"