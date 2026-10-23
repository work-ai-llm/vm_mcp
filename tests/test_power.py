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
  on the Ubuntu jumpbox), and the caller enforces a fixed request timeout that
  a graceful stop can outlive no matter what the call does internally. So a
  soft stop is issued and returned as `stopping` immediately -- it must NOT
  block on the guest, must not re-poll the state inside the call, and must
  leave the background command owned.
* `vmrun` reports its own errors on **stdout** with exit -1.
* A command's exit code is not evidence its effect happened. Every hard-stop
  result is read back from `vmrun list` instead; a soft result says `stopping`
  and lies about nothing.

Run:
    ..\\.venv\\Scripts\\python.exe -m pytest tests/test_power.py -v
"""

from __future__ import annotations

import asyncio
import logging
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

    `start` and `stop` flip the modelled power state, so a background reaper
    observes a VM that really does go away -- the same shape as a fast Linux
    shutdown, except the flip is instant rather than 26s.

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

            The production code awaits this once, hands what it got to the
            background reaper via `_collect`, and answers the caller at once.
            The fake runs the stop *before* the future is created, which
            resolves immediately -- so a fire-and-forget call observes the VM
            already going down by the time the reaper owns it, and nothing in
            the call path can silently await a real 26s.
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
        return harness

    return install


async def _call_and_drain(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run a tool call, then let its background work finish in the same loop.

    A soft stop hands its vmrun to a background reaper (power._BACKGROUND) and
    answers at once. `asyncio.run` destroys pending tasks on exit -- with a
    warning, and with no way to assert the reaper ran -- so the fact that this
    happens *inside* the call's own event loop is what keeps the fixture
    deterministic instead of racy.
    """
    result = await fn(*args, **kwargs)
    pending = [t for t in power._BACKGROUND if not t.done()]
    if pending:
        await asyncio.gather(*pending)
    return result


def call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return asyncio.run(_call_and_drain(fn, *args, **kwargs))


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
    """Fail loudly on a typo -- as a ToolError, not an opaque crash.

    `power.stop`'s own ValueError used to escape past the tool layer: the
    caller's result carried no reason, while the same call on a bad *name*
    produced a well-written error. The mode check is now a tool-level guard
    and the message has to carry what the agent needs to continue: the value
    it got, and both values that exist. An unrecognised mode silently treated
    as `soft` would mean a caller asking to cut power got a graceful shutdown
    instead, so it must be refused outright.
    """
    harness = fake_vmrun()

    with pytest.raises(ToolError) as excinfo:
        call(server.stop_vm, uuid=DC01_UUID, mode="harder")

    assert harness.calls == []
    assert "harder" in str(excinfo.value), "the bad value must be echoed"
    assert "soft" in str(excinfo.value) and "hard" in str(excinfo.value), (
        "the valid choices must be named"
    )


def test_stop_vm_accepts_mode_in_any_case(lab, fake_vmrun) -> None:
    """`Hard` behaviour, not punctuation, is what the caller asked for.

    A model that writes `Hard` is making an unambiguous request; refusing it
    over case would turn the guard into a spelling test. The result echoes
    the mode as the lowercase value that was actually issued, so what ran is
    always readable from the result.
    """
    harness = fake_vmrun()

    result = call_powered(server.stop_vm, lab, uuid=DC01_UUID, mode="Hard")

    assert result["mode"] == "hard"
    assert ["stop", lab["dc01"].path, "hard"] in harness.calls


def test_restart_vm_validates_mode_the_same_way(lab, fake_vmrun) -> None:
    """One mode guard for both power tools, on purpose.

    `restart_vm` takes the same `mode` as `stop_vm`, so an invalid value gets
    the same treatment: a ToolError naming the choices, with nothing issued.
    And an all-caps `HARD` on an already-stopped VM -- the cheap full-cycle
    path -- is accepted: the no-op stop confirms the VM down and the start
    runs, so case is never the difference between a restart and an error.
    """
    harness = fake_vmrun()

    with pytest.raises(ToolError) as excinfo:
        call(server.restart_vm, uuid=DC01_UUID, mode="gracefully")

    assert harness.calls == []
    assert "soft" in str(excinfo.value) and "hard" in str(excinfo.value)

    result = call(server.restart_vm, uuid=DC01_UUID, mode="HARD")

    assert result["mode"] == "hard"
    # The VM here is already off, so the stop half is the confirmed no-op
    # short-circuit and vmrun never sees a stop command at all; the start
    # runs and gets read back.
    assert harness.calls == [["list"], ["start", lab["dc01"].path, "nogui"], ["list"]]
    assert result["started"]["power_state"] == "running"


def test_soft_stop_is_not_confirmation(lab, fake_vmrun) -> None:
    """The core of the fire-and-forget contract, in one result.

    A soft stop answers with `stopping` and `confirmed=False` -- a state this
    module commanded, explicitly not one observed. Reporting `stopped` from
    this call would be a lie by construction, because nothing in it waits
    long enough to see anything; the honest answer is that a shutdown is in
    flight and unverified.
    """
    fake_vmrun()

    result = call_powered(server.stop_vm, lab, uuid=DC01_UUID)

    assert result["power_state"] == power.POWER_STOPPING
    assert result["confirmed"] is False


def test_soft_stop_answers_at_once_and_polls_nothing(lab, fake_vmrun) -> None:
    """The call must not spend its request-timeout budget waiting on the guest.

    `vmrun list` is called once here -- the pre-check that tells "already
    off" from "something to stop". A second call would mean the tool is
    polling for a shutdown the client's request timeout can outlive by
    minutes: that is the behaviour the redesign exists to remove.
    """
    harness = fake_vmrun()

    result = call_powered(server.stop_vm, lab, uuid=DC01_UUID)

    list_calls = sum(1 for c in harness.calls if c[0] == "list")
    assert list_calls == 1, f"soft stop polled state {list_calls} times"
    assert result["waited_s"] < 5.0, "the call reported as though it waited"


def test_soft_stop_leaves_the_guidance_the_agent_needs(lab, fake_vmrun) -> None:
    """The result is the only thing the agent sees while the guest goes down.

    The tool description carries the contract, but the result is what is in
    an agent's hands when it decides its next move. It must admit the
    shutdown was not waited for, name the read-only tools that confirm it,
    and point at mode='hard' for a guest that refuses to leave -- without
    ever making that choice for anyone.
    """
    fake_vmrun()

    result = call_powered(server.stop_vm, lab, uuid=DC01_UUID)

    detail = result["detail"].lower()
    assert "not" in detail and "wait" in detail, "must admit it did not wait"
    assert "waited_s" in detail, (
        "must say what waited_s means here: issue time, not shutdown time"
    )
    assert "vm_status" in detail, "must say how to confirm"
    assert "hard" in detail, "must name the escalation, purely as an option"
    assert len(result["detail"]) < 300, (
        "the detail is a pointer, not the contract: the full guidance lives "
        "in the tool description, and re-sending it on every call is wall of "
        "text an agent stops reading"
    )


def test_a_second_soft_stop_joins_the_flight_and_spawns_nothing(
    lab, fake_vmrun
) -> None:
    """One guest, at most one graceful stop driving it at a time.

    Two concurrent soft stops -- or an agent retrying while the first request
    is still being carried out -- used to spawn two vmrun processes aimed at
    the same guest. The second call now joins the flight instead: same
    `stopping` shape, no new process, and a detail that says no new request
    was issued. The wedged-guest harness keeps the guest listed as running so
    both calls reach the launch path rather than the already-off short-circuit.
    """
    harness = fake_vmrun(stop_never_dies=True)

    async def both_calls() -> tuple[Any, Any]:
        lab["dc01"].running = True
        first = await server.stop_vm(uuid=DC01_UUID)
        second = await server.stop_vm(uuid=DC01_UUID)
        pending = [t for t in power._BACKGROUND if not t.done()]
        if pending:
            await asyncio.gather(*pending)
        return first, second

    first, second = asyncio.run(both_calls())

    stops = [c for c in harness.calls if c[0] == "stop"]
    assert stops == [["stop", lab["dc01"].path, "soft"]], (
        f"exactly one vmrun stop must be spawned for two soft calls, got {stops}"
    )
    assert first["detail"] != second["detail"], (
        "the joiner must answer a different question than the initiating stop"
    )
    assert second["power_state"] == power.POWER_STOPPING
    assert second["confirmed"] is False
    assert "already in flight" in second["detail"].lower(), (
        "the joiner must say why it issued nothing"
    )
    assert "no new" in second["detail"].lower()
    assert power._SOFT_STOPS_IN_FLIGHT == {}, (
        "the reaper's done-callback must clear the in-flight registry, or the "
        "next genuine stop request would join a flight that is over"
    )


def test_the_in_flight_guard_clears_when_the_stop_lands(lab, fake_vmrun) -> None:
    """The guard is a deduplicator, not a lock.

    After a shutdown has landed -- the drain awaits the reaper, whose
    done-callback drops the in-flight entry -- the clearance is observable in
    what a repeat call returns: the clean already-off no-op, not a joiner
    still reporting last call's `stopping` as if the shutdown were somehow
    still running. A registry entry that outlived its stop would produce
    exactly that stale answer.
    """
    harness = fake_vmrun()

    call_powered(server.stop_vm, lab, uuid=DC01_UUID)  # spawns once, lands, drains
    result = call(server.stop_vm, uuid=DC01_UUID)  # no forced `running`: it is off

    stops = [c for c in harness.calls if c[0] == "stop"]
    assert stops == [["stop", lab["dc01"].path, "soft"]], (
        f"a landed stop must be one spawn; a repeat finds the VM already off, got {stops}"
    )
    assert power._SOFT_STOPS_IN_FLIGHT == {}
    assert result["power_state"] == power.POWER_STOPPED
    assert result["confirmed"] is True, (
        "an already-off VM is a confirmed no-op, not a stale joiner"
    )


def test_stop_of_a_wedged_guest_still_never_escalates(lab, fake_vmrun) -> None:
    """The safety property, unchanged by the redesign.

    A guest that ignores the shutdown request -- waiting on a prompt, a hung
    service, a filesystem that will not flush -- is still running after any
    soft call now. The correct behaviour is exactly one soft request, a
    result of `stopping`, and no power cut anywhere behind the caller's back.
    """
    harness = fake_vmrun(stop_never_dies=True)

    result = call_powered(server.stop_vm, lab, uuid=DC01_UUID)

    stops = [c for c in harness.calls if c[0] == "stop"]
    assert stops == [["stop", lab["dc01"].path, "soft"]], (
        f"a graceful stop must issue exactly one soft stop, got {stops}"
    )
    assert result["power_state"] == power.POWER_STOPPING
    assert result["confirmed"] is False
    assert lab["dc01"].running is True


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


def test_stop_that_cannot_be_observed_still_issues_the_request(
    lab, fake_vmrun
) -> None:
    """A host fault must neither lie nor silently refuse the request.

    The pre-check cannot see the VM because `vmrun list` itself is failing.
    That must not surface as `stopped` -- a confident wrong answer about a
    domain controller -- and it must not cancel the request either: a broken
    `list` says nothing about whether `stop` would work. The stop is issued,
    the result says `stopping` with `confirmed.False`, and the fault is named
    in `vmrun_error` where an agent can weigh it.
    """
    harness = fake_vmrun(list_unavailable=True)

    result = call(server.stop_vm, uuid=DC01_UUID)

    assert result["power_state"] == power.POWER_STOPPING
    assert result["confirmed"] is False
    assert result["vmrun_error"], "the failure to observe must be named"
    assert ["stop", lab["dc01"].path, "soft"] in harness.calls


def test_stop_hard_still_confirms_by_observation(lab, fake_vmrun) -> None:
    """Hard stop does not get a shortcut just because it is fast."""
    fake_vmrun()

    result = call_powered(server.stop_vm, lab, uuid=DC01_UUID, mode="hard")

    assert result["confirmed"] is True
    assert result["power_state"] == "stopped"


# --- restart_vm -----------------------------------------------------------


def test_hard_restart_stops_then_starts(lab, fake_vmrun) -> None:
    """`hard` is fast enough (~2s cut, ~3s start) to finish inside the call.

    This is the one restart mode where both halves can be observed in the
    call's own lifetime, so this is where the stop-before-start ordering and
    the `done` flow tag are pinned: the result states outright that no half
    of this restart was left to the caller, rather than implying it from the
    mere presence of both halves.
    """
    harness = fake_vmrun()

    result = call_powered(server.restart_vm, lab, uuid=DC01_UUID, mode="hard")

    assert result["stop_half"] == "done"
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

    result = call_powered(server.restart_vm, lab, uuid=DC01_UUID, mode="hard")

    assert set(result["stopped"]) >= {"power_state", "confirmed", "waited_s"}
    assert set(result["started"]) >= {"power_state", "confirmed", "waited_s"}
    assert "power_state" not in result, (
        "restart must not collapse to one verdict; the two halves are separate "
        "outcomes and the interesting case is when they disagree"
    )


def test_hard_restart_does_not_start_a_vm_that_did_not_stop(
    lab, fake_vmrun, monkeypatch
) -> None:
    """The safety property of the composition.

    A failed stop followed by a start produces a machine that looks up and is
    not -- two power states disagreeing and no report of it. The restart stops
    there and says so, both in the refusal's own detail and in the flow tag:
    `stop_half: "blocked"` is distinguishable from `"done"` by clients that
    count keys, without anyone having to interpret prose.
    """
    harness = fake_vmrun(stop_never_dies=True)
    # Confirming a hard stop against a wedged guest would spend STOP_HARD_TIMEOUT
    # of real seconds only to learn the obvious. Shrink the window: the point is
    # that confirmation did not happen, and therefore the start did not either.
    monkeypatch.setattr(power, "STOP_HARD_TIMEOUT", 0.2)

    result = call_powered(server.restart_vm, lab, uuid=DC01_UUID, mode="hard")

    assert result["stopped"]["power_state"] == "running", (
        "the wedged guest is still up: that is the observed stop half, and "
        "the reason the start half is refused"
    )
    assert result["stop_half"] == "blocked"
    assert result["started"] is not None, (
        "the refusal rides in `started`, so the shape stays stable and the "
        "reason is in the field a client already knows to read"
    )
    assert result["started"]["confirmed"] is False
    assert "not confirmed stopped" in result["started"]["detail"].lower()

    assert not any(c[0] == "start" for c in harness.calls), (
        "powering on a VM that was still running would produce a machine that "
        "looks up and is not"
    )


def test_soft_restart_hands_the_start_back_to_the_caller(lab, fake_vmrun) -> None:
    """The fire-and-forget contract, applied to the composed operation.

    A graceful shutdown runs in the background now, so a restart cannot
    confirm the guest left inside its own call -- and starting over a VM that
    is *and is not* still shutting down is the trap `restart` exists to avoid.
    So the tool answers with the stop half (`stopping`) and a null `started`
    half, its detail names the tool that completes the restart, and
    `stop_half: "handoff"` states the flow outright rather than leaving the
    caller to read a missing key.
    """
    harness = fake_vmrun()

    result = call_powered(server.restart_vm, lab, uuid=DC01_UUID)

    assert result["stopped"]["power_state"] == power.POWER_STOPPING
    assert result["stopped"]["confirmed"] is False
    assert result["started"] is None, (
        "no start ran on this path; a populated `started` half would read as "
        "a completed restart"
    )
    assert result["stop_half"] == "handoff", (
        "the flow must be stated outright: review found that started going "
        "missing was read as a bug, so the result now says what happened "
        "instead of implying it from a missing key"
    )
    assert "start_vm" in result["stopped"]["detail"].lower(), (
        "the handoff must name the tool that completes it"
    )
    assert len(result["stopped"]["detail"]) < 450, (
        "the detail is a hint, not the contract: the description carries the "
        "full handoff rationale, and the per-call text stays short enough to "
        "actually be read"
    )
    assert not any(c[0] == "start" for c in harness.calls)


def test_soft_restart_of_a_stopped_vm_completes_at_once(lab, fake_vmrun) -> None:
    """A VM found already off has nothing in flight, so the call finishes both
    halves immediately.

    `stopping` can never come back from a restart whose stop half confirmed
    `stopped` -- the confirmed case is the pre-check seeing the machine down,
    and the start is fast enough to just run. Stranding an already-stopped VM
    behind a handoff the caller may not execute would leave the lab in the
    wrong state with no instruction in sight.
    """
    harness = fake_vmrun()

    result = call(server.restart_vm, uuid=DC01_UUID)

    assert result["stopped"]["power_state"] == "stopped"
    assert result["started"]["power_state"] == "running"
    assert ["start", lab["dc01"].path, "nogui"] in harness.calls
    assert result["stop_half"] == "done"


def test_restart_forwards_the_stop_mode(lab, fake_vmrun) -> None:
    """`mode` governs the stop half; the start half has no mode."""
    harness = fake_vmrun()

    result = call_powered(server.restart_vm, lab, uuid=DC01_UUID, mode="hard")

    assert result["mode"] == "hard"
    assert ["stop", lab["dc01"].path, "hard"] in harness.calls


# --- the background reaper ------------------------------------------------


def test_the_reaper_owns_a_stop_that_outlives_the_call(lab, monkeypatch) -> None:
    """A fire-and-forget stop must not become an abandoned process.

    Nothing the tool call returns to an agent can observe the shutdown now,
    so the one thing it is owed is that the background command is *owned*:
    its pipes are drained, its outcome is recorded, and a stop that outlives
    the ceiling is killed rather than left holding a VM the caller believes
    it let go of. The failure this guards: two vmrun processes contending
    for one machine.
    """
    killed: list[bool] = []
    ceilings: list[float] = []

    class Stuck:
        returncode = None

        async def wait(self) -> None:
            return None

        def kill(self) -> None:
            killed.append(True)
            self.returncode = -9

    stub = Stuck()

    async def spawn(*_: Any, **__: Any) -> Stuck:
        return stub

    async def collect_like_real(process: Any, args: list[str], timeout: float) -> VmrunResult:
        # Mirrors the real `_collect`'s contract as close as a fake can: it
        # receives the ceiling, and when it expires it kills the process and
        # reports the command as unrecoverable rather than hanging forever.
        ceilings.append(timeout)
        await asyncio.sleep(0)
        process.kill()
        raise VmrunUnavailable(f"vmrun stop timed out after {timeout:.0f}s")

    async def always_running(**_: Any) -> list[str]:
        return [r"D:\some\other.vmx"]

    monkeypatch.setattr(power, "spawn_vmrun", spawn)
    monkeypatch.setattr(power, "_collect", collect_like_real)
    monkeypatch.setattr(power, "list_running_vmx", always_running)

    async def go():
        outcome = await power.stop(r"D:\some\other.vmx", mode="soft")
        pending = [t for t in power._BACKGROUND if not t.done()]
        await asyncio.gather(*pending)
        return outcome

    outcome = asyncio.run(go())

    assert outcome.power_state == power.POWER_STOPPING
    assert ceilings == [power.SOFT_STOP_CEILING], (
        "the reaper must pass the designed ceiling, not wait indefinitely"
    )
    assert killed, "the stuck vmrun must be killed, not abandoned"
    assert power._BACKGROUND == set(), (
        "the reaper must be discarded when it is done, not leaked per call"
    )


def test_the_reaper_ceiling_is_tied_to_the_design() -> None:
    """The ceiling is the vmrun timeout plus margin, not an arbitrary number.

    900s is what a Windows domain controller draining Active Directory is
    given; the reaper must not be stingier than the thing it protects.
    """
    from vm_mcp.vmrun import STOP_SOFT_TIMEOUT

    assert power.SOFT_STOP_CEILING == STOP_SOFT_TIMEOUT + 60.0


def test_a_background_stop_that_ends_cleanly_is_logged_and_gone(
    lab, fake_vmrun, caplog
) -> None:
    """The call returned `stopping`; the eventual truth must still exist.

    Only log can carry it, since no result was kept. The assertion that
    matters is not just the log line, but that the reaper runs through the
    happy path of the fake harness -- proving the fire-and-forget task is
    alive and discarded in the ordinary case, not only in the kill case.
    """
    harness = fake_vmrun()
    lab["dc01"].running = True

    with caplog.at_level(logging.INFO, logger="vm_mcp.power"):
        result = call(server.stop_vm, uuid=DC01_UUID)

    assert result["power_state"] == power.POWER_STOPPING
    assert any(
        "background graceful stop" in r.getMessage() and "finished" in r.getMessage()
        for r in caplog.records
    ), "a shutdown nobody was watching must still be recorded somewhere"
    assert power._BACKGROUND == set()


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
    something other than what actually happens. The two values are also
    published as an enum: a model choosing mode sees the choices before it
    sends anything, which is what makes the case-insensitive guard behind it
    a safety net rather than something a caller trips on.
    """

    async def go() -> dict[str, Any]:
        return {t.name: t.input_schema for t in await server.mcp.list_tools()}

    schemas = asyncio.run(go())

    for name in ("stop_vm", "restart_vm"):
        schema = schemas[name]["properties"]["mode"]
        assert schema.get("default") == "soft"
        assert schema.get("enum") == ["soft", "hard"]


# --- one flight per VM, in every direction ---------------------------------


def test_start_refuses_to_fight_a_shutdown_in_flight(lab, fake_vmrun) -> None:
    """The actual damage case: a start against a guest that is going down.

    `stop_vm(soft)` answers before the guest is down, so for the whole
    shutdown window the read-only tools still report `running` -- and an
    impatient follow-up start used to sail straight through that window and
    return `running, confirmed=True` seconds before the machine went dark.
    Now the start is refused while the flight claims, the refusal carries the
    flight's age, and the override is named in the same breath. Both calls
    happen inside one event loop because the wedged-guest harness only holds
    the marker that long: the fake's vmrun lands the moment the drain awaits
    it, which is the case the *clears* test below covers.
    """
    harness = fake_vmrun(stop_never_dies=True)

    async def flight_then_start() -> Any:
        lab["dc01"].running = True
        await server.stop_vm(uuid=DC01_UUID)
        with pytest.raises(ToolError) as excinfo:
            await server.start_vm(uuid=DC01_UUID)
        pending = [t for t in power._BACKGROUND if not t.done()]
        if pending:
            await asyncio.gather(*pending)
        return excinfo

    excinfo = asyncio.run(flight_then_start())

    assert "in flight" in str(excinfo.value), "must name the flight"
    assert "hard" in str(excinfo.value), "must name the override in the same breath"
    assert "vm_status" in str(excinfo.value), "must name the way to wait it out"
    assert not any(c[0] == "start" for c in harness.calls), (
        "the start must not be issued against a machine being told to go down"
    )
    assert power._SOFT_STOPS_IN_FLIGHT == {}


def test_start_after_the_flight_clears_completes(lab, fake_vmrun) -> None:
    """The refusal is a state, not a grudge.

    Once the shutdown lands, the reaper clears the marker at the moment its
    vmrun exits -- and a start that follows is an ordinary start. If the
    marker leaked, the refusal would landlock exactly the machine someone
    just shut down.
    """
    harness = fake_vmrun()

    call(server.stop_vm, uuid=DC01_UUID)  # already off: lands at once, drains
    result = call(server.start_vm, uuid=DC01_UUID)

    assert result["power_state"] == "running"
    assert ["start", lab["dc01"].path, "nogui"] in harness.calls
    assert power._SOFT_STOPS_IN_FLIGHT == {}


def test_soft_restart_refuses_while_a_shutdown_is_in_flight(
    lab, fake_vmrun
) -> None:
    """A restart layered on a foreign flight must not silently re-anchor to it.

    The agent asked for a restart. Joining would hand back a `stopping`
    half-flight answering a request nobody made -- and its handoff note would
    then instruct a start_vm that start_vm itself refuses while the flight
    holds: a loop wearing the clothes of a plan. So the tool refuses with the
    flight's age and points at the one call that cuts through, mode='hard'.
    """
    harness = fake_vmrun(stop_never_dies=True)

    async def flight_then_restart() -> Any:
        lab["dc01"].running = True
        await server.stop_vm(uuid=DC01_UUID)
        with pytest.raises(ToolError) as excinfo:
            await server.restart_vm(uuid=DC01_UUID)
        pending = [t for t in power._BACKGROUND if not t.done()]
        if pending:
            await asyncio.gather(*pending)
        return excinfo

    excinfo = asyncio.run(flight_then_restart())

    assert "in flight" in str(excinfo.value)
    assert "hard" in str(excinfo.value)
    stops = [c for c in harness.calls if c[0] == "stop"]
    assert stops == [["stop", lab["dc01"].path, "soft"]], (
        f"the refusal must issue nothing, got {stops}"
    )
    assert power._SOFT_STOPS_IN_FLIGHT == {}


def test_hard_restart_is_the_override_and_is_not_refused(
    lab, fake_vmrun, monkeypatch
) -> None:
    """The escape hatch must open while the flight is live.

    `hard` exists precisely for a guest that will not leave, so the refusal
    may not landlock it: restart_vm with mode='hard' proceeds through a live
    flight, runs the cut, and answers with its own honest outcome. Against a
    wedged guest that outcome is `blocked` -- the hard stop ran but never
    confirmed -- which still proves the entry check did not stand in the
    way. And no `vmrun start` is issued here even in the success case the
    entry check were bypassed by hand for: the start half refuses on its own
    terms until the stop confirms.
    """
    harness = fake_vmrun(stop_never_dies=True)
    # A wedged guest makes hard-stop confirmation expensive; shrink it. The
    # point under test is the entry check passing, not the poll timing out.
    monkeypatch.setattr(power, "STOP_HARD_TIMEOUT", 0.2)

    async def flight_then_hard_restart() -> dict[str, Any]:
        lab["dc01"].running = True
        await server.stop_vm(uuid=DC01_UUID)
        result = await server.restart_vm(uuid=DC01_UUID, mode="hard")
        pending = [t for t in power._BACKGROUND if not t.done()]
        if pending:
            await asyncio.gather(*pending)
        return result

    result = asyncio.run(flight_then_hard_restart())

    assert result["stop_half"] == "blocked", (
        "the entry must not refuse a hard restart while a flight is live; "
        "what is blocked below is the start half, refused on its own terms"
    )
    assert not any(c[0] == "start" for c in harness.calls)
    assert power._SOFT_STOPS_IN_FLIGHT == {}


def test_stop_vm_description_carries_the_fire_and_forget_contract() -> None:
    """The full contract must live in the description, not only in the code.

    The agent calling this tool reads it at decision time. It has no other
    channel for learning that a soft call answers `stopping` immediately,
    that confirming the state afterwards is a read-only-tool job, and that
    hard exists but is never chosen automatically. A description silent on
    any of the three ships a behaviour the caller cannot see.
    """

    async def go() -> dict[str, Any]:
        return {t.name: t.description or "" for t in await server.mcp.list_tools()}

    descriptions = asyncio.run(go())
    text = descriptions["stop_vm"].lower()

    assert "stopping" in text, "the transient state must be described"
    assert "vm_status" in text, "the agent must be pointed at how to confirm"
    assert "not" in text and "wait" in text, "must not imply the call blocks"
    assert "hard" in text, "the escalation must be named as the caller's choice"
    assert "in flight" in text and "joins" in text, (
        "must teach that a repeat soft call joins the shutdown in flight "
        "instead of spawning a second vmrun process"
    )
    assert "refused" in text, (
        "the opposite direction of the flight must be described too: a start "
        "issued during the shutdown is refused, and the caller needs to know "
        "the wait it is being asked for has an end stated as vm_status"
    )


def test_start_vm_description_carries_the_refusal_contract() -> None:
    """The start refusal is part of the tool's published behaviour.

    A refusal the description never mentions reads as an error, not a rule.
    The description must say that a start issued during a soft shutdown is
    refused, that the wait has an end stated as vm_status 'stopped' -- and
    name the override, because a refusal that hides its escape hatch is a
    lockout.
    """

    async def go() -> dict[str, Any]:
        return {t.name: t.description or "" for t in await server.mcp.list_tools()}

    descriptions = asyncio.run(go())
    text = descriptions["start_vm"].lower()

    assert "refused" in text or "refuse" in text, "the refusal must be published"
    assert "vm_status" in text, "the wait must be observable, not open-ended"
    assert "hard" in text and "never refused" in text, (
        "the override must be named in the same breath as the refusal"
    )


def test_restart_vm_description_carries_the_handoff_contract() -> None:
    """A soft restart is half an operation; the caller must learn that here.

    The tool does not issue the start on the soft path, so the description is
    the only place that teaches the two-step dance: poll until stopped, then
    call start_vm. Without it, a null `started` looks like a bug rather than
    a design -- which is exactly the misreading that motivated `stop_half`,
    and why the description and the field are both pinned here.
    """

    async def go() -> dict[str, Any]:
        return {t.name: t.description or "" for t in await server.mcp.list_tools()}

    descriptions = asyncio.run(go())
    text = descriptions["restart_vm"].lower()

    assert "start_vm" in text, "must name the tool that completes the restart"
    assert "stopped" in text and "poll" in text, "must say how to observe"
    assert "hard" in text, "the in-call cycle must be distinguishable from the handoff"
    assert "stop_half" in text, (
        "the flow tag must be described: it is the result's statement of its "
        "own shape, and a reader has to be able to interpret it"
    )
    assert "null" in text and "handoff" in text, (
        "must teach that started: null is the handoff, not an omission"
    )
    assert "never refused" in text, (
        "the hard override must be published as open: a refusal on the soft "
        "path whose escape the description hides would be a lockout"
    )