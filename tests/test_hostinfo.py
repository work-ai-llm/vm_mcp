"""Tests for `host_resources` and the `hostinfo` module behind it.

No VMware process is started and no VM is touched. `host_resources` is the only
tool that reads nothing but the host, so everything here is exercisable without
hardware -- `psutil` is replaced wholesale, not mocked piecemeal.

What is pinned, and why each of these was a real decision:

  * **A sample window that catches no CPU ticks reports `None`, not 0 or 100.**
    Windows CPU counters tick at ~15.6 ms. A short window can legitimately span
    zero ticks, and dividing by that zero would yield a confident, wrong number.
  * **Steal time is not busy time.** `steal`/`softirq` are time lost to the
    hypervisor; counting them as busy reports a loaded host on an idle one.
  * **One unreadable volume does not fail the call.** `E:\\` on the M1 host raises
    `WinError 21`, and losing the C: and D: readings over it would be a worse
    answer than reporting the error alongside the volumes that answered.
  * **A stopped VM is absent from `vm_memory`, not reported as zero.** Absent and
    zero are different claims: one means "not running", the other means "running
    and configured with nothing".
  * **When `vmrun` is unreachable, `vm_memory` and `headroom_gib` are withheld.**
    Without vmrun the running set is unknown, so both would be built from the
    wrong VMs while looking perfectly well-formed.
  * **`headroom_gib` is subtraction, not advice.** There is deliberately no
    "will another VM fit" field, and the tests assert the absence of one.

Run:
    ..\\.venv\\Scripts\\python.exe -m pytest tests/test_hostinfo.py -v
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable

import pytest

from vm_mcp import hostinfo, roster, server

from test_vm_mcp import FakeVmrun, call

# --- fixtures ------------------------------------------------------------

RUNNING_VMX = r"D:\vms\goad\GOAD-DC01\WindowsServer2019.vmx"
STOPPED_VMX = r"C:\VMs\wazuh\wazuh-4.7.5.vmx"

DC01_UUID = "56 4d f4 8b bf be 94 a5-f8 b5 17 60 df 89 9e 33"
WAZUH_UUID = "56 4d e0 b5 86 57 4b 06-5c 82 f2 7e 01 37 b4 1d"

REGISTRY = "\r\n".join(
    [
        '.encoding = "windows-1251"',
        f'vmlist1.config = "{RUNNING_VMX}"',
        'vmlist1.DisplayName = "provider: GOAD-DC01"',
        f'vmlist1.UUID = "{DC01_UUID}"',
        f'vmlist2.config = "{STOPPED_VMX}"',
        'vmlist2.DisplayName = "wazuh-4.7.5"',
        f'vmlist2.UUID = "{WAZUH_UUID}"',
    ]
).encode("windows-1251")

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


class FakeVolume:
    """One `psutil.disk_partitions()` entry."""

    def __init__(self, device: str, mountpoint: str, fstype: str = "NTFS",
                 opts: str = "rw,fixed") -> None:
        self.device = device
        self.mountpoint = mountpoint
        self.fstype = fstype
        self.opts = opts


class FakeUsage:
    def __init__(self, total: int, used: int, free: int) -> None:
        self.total = total
        self.used = used
        self.free = free
        self.percent = round(100 * used / total, 1) if total else 0.0


class FakeVirtual:
    def __init__(self, total: int, available: int) -> None:
        self.total = total
        self.available = available
        self.percent = round(100 * (total - available) / total, 1)


GIB = 1024**3
MIB = 1024**2


def fake_psutil(
    monkeypatch: pytest.MonkeyPatch,
    *,
    total_gib: int = 32,
    available_gib: int = 8,
    volumes: list[tuple[FakeVolume, FakeUsage | OSError]] | None = None,
    vmware_rss_mib: int = 6800,
) -> dict[str, Any]:
    """Install a fake psutil across `hostinfo` and `server`.

    Both modules matter: `server` imports psutil directly for the headroom
    subtraction, so patching only `hostinfo` would leave the real host's numbers
    in half the result.
    """
    spec: dict[str, Any] = {}

    virtual = FakeVirtual(total_gib * GIB, available_gib * GIB)
    monkeypatch.setattr(hostinfo.psutil, "virtual_memory", lambda: virtual)
    monkeypatch.setattr(server.psutil, "virtual_memory", lambda: virtual)
    monkeypatch.setattr(
        hostinfo.psutil, "swap_memory", lambda: FakeUsage(6 * GIB, 1 * GIB, 5 * GIB)
    )

    parts = volumes if volumes is not None else [
        (FakeVolume("C:\\", "C:\\"), FakeUsage(400 * GIB, 280 * GIB, 120 * GIB)),
    ]
    monkeypatch.setattr(
        hostinfo.psutil,
        "disk_partitions",
        lambda all=False: [p for p, _ in parts],  # noqa: A002
    )
    usage_map = {p.mountpoint: u for p, u in parts}

    def fake_usage(mountpoint: str) -> FakeUsage:
        outcome = usage_map[mountpoint]
        if isinstance(outcome, OSError):
            raise outcome
        return outcome

    monkeypatch.setattr(hostinfo.psutil, "disk_usage", fake_usage)

    monkeypatch.setattr(hostinfo.psutil, "cpu_count", lambda logical=True: 4)
    monkeypatch.setattr(
        hostinfo.psutil, "cpu_freq", lambda: type("F", (), {"current": 3600.0})()
    )
    monkeypatch.setattr(hostinfo.psutil, "boot_time", lambda: 1_700_000_000.0)
    monkeypatch.setattr(
        hostinfo.psutil,
        "cpu_times",
        lambda: type(
            "T", (), {"user": 100.0, "system": 50.0, "idle": 400.0,
                      "interrupt": 1.0, "dpc": 1.0}
        )(),
    )
    monkeypatch.setattr(hostinfo.psutil, "NoSuchProcess", type("NoSuchProcess", (Exception,), {}))
    monkeypatch.setattr(hostinfo.psutil, "AccessDenied", type("AccessDenied", (Exception,), {}))

    # No sleep: the fake cpu_times is constant, so the window is irrelevant.
    async def instant_cpu_load(window_s: float = hostinfo.CPU_SAMPLE_WINDOW) -> hostinfo.CpuSample:
        return hostinfo.CpuSample(percent=42.0, window_s=window_s, busy_s=0.5, idle_s=0.5)

    monkeypatch.setattr(hostinfo, "cpu_load", instant_cpu_load)

    class FakeProc:
        def __init__(self, name: str, rss: int) -> None:
            self.info = {
                "name": name,
                "memory_info": type("M", (), {"rss": rss})(),
            }

    procs = [
        FakeProc("vmware-vmx.exe", vmware_rss_mib * MIB),
        FakeProc("vmware.exe", 55 * MIB),
        FakeProc("explorer.exe", 120 * MIB),
    ]
    monkeypatch.setattr(
        hostinfo.psutil, "process_iter", lambda attrs: iter(procs)
    )

    spec["virtual"] = virtual
    return spec


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Synthetic lab: registry + two real .vmx files, wired into the module."""
    vmx_dir = tmp_path / "vmx"
    vmx_dir.mkdir()
    dc01 = vmx_dir / "dc01.vmx"
    dc01.write_text(DC01_VMX, encoding="utf-8")
    wazuh = vmx_dir / "wazuh.vmx"
    wazuh.write_text(WAZUH_VMX, encoding="utf-8")

    registry_file = tmp_path / "inventory.vmls"
    registry_file.write_bytes(
        REGISTRY.replace(RUNNING_VMX.encode(), str(dc01).encode()).replace(
            STOPPED_VMX.encode(), str(wazuh).encode()
        )
    )
    monkeypatch.setattr(roster, "inventory_path", lambda: registry_file)

    return {"registry": registry_file, "running_vmx": str(dc01)}


@pytest.fixture
def vmrun(monkeypatch: pytest.MonkeyPatch) -> Callable[..., FakeVmrun]:
    def install(**kwargs: Any) -> FakeVmrun:
        fake = FakeVmrun(**kwargs)
        monkeypatch.setattr(server, "list_running_vmx", fake.list_running_vmx)
        monkeypatch.setattr(server, "tools_state", fake.tools_state)
        return fake

    return install


# --- CPU sampling --------------------------------------------------------


def test_cpu_load_reads_as_percentage_across_all_cores() -> None:
    """Busy/total, not busy/busy+something-guessed."""
    before = type("T", (), {"user": 100.0, "system": 50.0, "idle": 400.0})()
    after = type("T", (), {"user": 101.0, "system": 50.5, "idle": 402.0})()
    times = iter([before, after])

    sample = hostinfo.sample_cpu(0.01, times=lambda: next(times), sleep=lambda _: None)

    # busy = (101-100) + (50.5-50) = 1.5; idle = 2.0; total = 3.5
    assert sample.busy_s == pytest.approx(1.5)
    assert sample.idle_s == pytest.approx(2.0)
    assert sample.percent == pytest.approx(42.9, abs=0.1)


def test_cpu_load_reports_none_when_window_catches_no_ticks() -> None:
    """The Windows ~15.6 ms tick case. 0/0 must not become 0% or 100%."""
    frozen = type("T", (), {"user": 100.0, "system": 50.0, "idle": 400.0})()
    times = iter([frozen, frozen])

    sample = hostinfo.sample_cpu(0.01, times=lambda: next(times), sleep=lambda _: None)

    assert sample.percent is None, "a zero-total window is 'not measured', not 0 or 100"
    assert sample.busy_s == 0.0
    assert sample.idle_s == 0.0


def test_cpu_load_excludes_steal_from_busy() -> None:
    """Steal is time lost to the hypervisor, not work this host did."""
    linux_before = type(
        "T", (), {"user": 10.0, "system": 5.0, "idle": 80.0, "steal": 0.0,
                  "nice": 0.0, "iowait": 0.0, "irq": 0.0, "softirq": 0.0}
    )()
    linux_after = type(
        "T", (), {"user": 11.0, "system": 5.0, "idle": 80.0, "steal": 4.0,
                  "nice": 0.0, "iowait": 0.0, "irq": 0.0, "softirq": 0.0}
    )()
    times = iter([linux_before, linux_after])

    sample = hostinfo.sample_cpu(0.01, times=lambda: next(times), sleep=lambda _: None)

    # 1.0 busy, 4.0 stolen, 0 idle moved. Steal is not busy, so this is 100% idle
    # of the 5.0 that actually elapsed on the CPU -- not 80% busy.
    assert sample.busy_s == pytest.approx(1.0)
    assert sample.idle_s == pytest.approx(4.0)


def test_cpu_load_tolerates_platforms_without_nice_field() -> None:
    """Windows scputimes has no `nice`. Naming it would raise AttributeError."""
    windows = type("T", (), {"user": 1.0, "system": 1.0, "idle": 1.0})()
    sample = hostinfo.sample_cpu(
        0.01, times=lambda: windows, sleep=lambda _: None
    )

    assert sample.percent is None  # no movement, but no crash


# --- volumes -------------------------------------------------------------


def test_one_unreadable_volume_does_not_lose_the_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`E:\\` raises WinError 21 on the M1 host and must not cost C: and D:."""
    fake_psutil(
        monkeypatch,
        volumes=[
            (FakeVolume("C:\\", "C:\\"), FakeUsage(400 * GIB, 280 * GIB, 120 * GIB)),
            (FakeVolume("E:\\", "E:\\"), OSError("[WinError 21] The device is not ready.")),
            (FakeVolume("D:\\", "D:\\"), FakeUsage(560 * GIB, 350 * GIB, 210 * GIB)),
        ],
    )

    volumes = hostinfo.host_volumes()

    assert len(volumes) == 3
    by_device = {v["device"]: v for v in volumes}
    assert by_device["C:\\"]["free_gib"] == pytest.approx(120.0, abs=0.01)
    assert by_device["D:\\"]["free_gib"] == pytest.approx(210.0, abs=0.01)
    assert "error" in by_device["E:\\"]
    assert "free_gib" not in by_device["E:\\"]


def test_removable_volume_is_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    """A USB disk is not where a 900 GiB lab should go."""
    fake_psutil(
        monkeypatch,
        volumes=[
            (FakeVolume("F:\\", "F:\\", opts="rw,removable"),
             FakeUsage(57 * GIB, 2 * GIB, 55 * GIB)),
        ],
    )

    assert hostinfo.host_volumes()[0]["removable"] is True


# --- the tool ------------------------------------------------------------


def test_host_resources_reports_cpu_memory_disk_and_vmware(
    lab: dict[str, Any], vmrun: Callable[..., FakeVmrun], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_psutil(monkeypatch)
    vmrun(list_result=type(
        "R", (), {"ok": True, "stdout": f"Total running VMs: 1\r\n{lab['running_vmx']}\r\n",
                  "exit_code": 0}
    )())

    result = call(server.host_resources)

    assert set(result) >= {"cpu", "memory", "volumes", "vmware", "vm_memory",
                           "headroom_gib", "uptime"}
    assert result["cpu"]["logical_cores"] == 4
    assert result["cpu"]["load_percent"] == 42.0
    assert result["memory"]["total_gib"] == 32.0
    assert result["memory"]["available_gib"] == 8.0
    assert result["vmware"]["process_count"] == 2
    # explorer.exe is not VMware and must not be counted.
    assert result["vmware"]["total_rss_gib"] < result["memory"]["total_gib"]


def test_stopped_vm_is_absent_not_zero(
    lab: dict[str, Any], vmrun: Callable[..., FakeVmrun], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stopped VM is missing, not running-with-no-memory.

    `wazuh` is registered and configured for 8 GiB but is not in `vmrun list`. It
    must not appear in `vm_memory`, and its 8 GiB must not be subtracted from
    available memory.
    """
    fake_psutil(monkeypatch)
    vmrun(list_result=type(
        "R", (), {"ok": True, "stdout": f"Total running VMs: 1\r\n{lab['running_vmx']}\r\n",
                  "exit_code": 0}
    )())

    result = call(server.host_resources)

    assert [v["name"] for v in result["vm_memory"]] == ["provider: GOAD-DC01"]
    # available 8 GiB - dc01 configured 3000 MiB (~2.93 GiB) = ~5.07 GiB.
    # If wazuh's 8 GiB were counted, this would be about -2.93.
    assert result["headroom_gib"] == pytest.approx(5.07, abs=0.02)


def test_vm_memory_exposes_configured_and_resident(
    lab: dict[str, Any], vmrun: Callable[..., FakeVmrun], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both numbers, so the gap between them is visible rather than guessed."""
    fake_psutil(monkeypatch, vmware_rss_mib=6800)
    vmrun(list_result=type(
        "R", (), {"ok": True, "stdout": f"Total running VMs: 1\r\n{lab['running_vmx']}\r\n",
                  "exit_code": 0}
    )())

    result = call(server.host_resources)

    vm = result["vm_memory"][0]
    assert vm["configured_gib"] == pytest.approx(2.93, abs=0.01)
    assert result["vmware"]["vmware_vmx_rss_gib"] == pytest.approx(6.64, abs=0.01)
    assert result["vmware"]["vmware_vmx_rss_gib"] > vm["configured_gib"]


def test_withholds_vm_memory_and_headroom_when_vmrun_unreachable(
    lab: dict[str, Any], vmrun: Callable[..., FakeVmrun], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unknown running set must not masquerade as an empty one.

    With vmrun down, every VM looks stopped. Reporting `vm_memory: []` and a
    headroom figure equal to all of available memory would read as "nothing is
    running, the host is wide open" -- the exact opposite of the truth.
    """
    fake_psutil(monkeypatch)
    from vm_mcp.vmrun import VmrunUnavailable

    vmrun(list_error=VmrunUnavailable("vmrun list failed (exit -1)"))

    result = call(server.host_resources)

    assert "vm_memory" not in result
    assert "headroom_gib" not in result
    assert "vm_memory_error" in result
    # The host readings that did not depend on vmrun are still there.
    assert result["memory"]["total_gib"] == 32.0
    assert result["volumes"]


def test_never_reports_a_will_it_fit_verdict(
    lab: dict[str, Any], vmrun: Callable[..., FakeVmrun], monkeypatch: pytest.MonkeyPatch
) -> None:
    """VMware's per-VM overhead is unobservable, so no verdict may be derived.

    PLAN.md §4 requires this explicitly. A boolean or a "fits" number here would
    be a guess wearing a measurement's clothes, and an agent acting on it would
    start a VM that cannot fit.
    """
    fake_psutil(monkeypatch)
    vmrun(list_result=type(
        "R", (), {"ok": True, "stdout": f"Total running VMs: 1\r\n{lab['running_vmx']}\r\n",
                  "exit_code": 0}
    )())

    result = call(server.host_resources)

    blob = repr(result).lower()
    for forbidden in ("will_fit", "fits", "can_start", "recommend", "sufficient",
                      "another_vm"):
        assert forbidden not in blob, f"{forbidden!r} implies a capacity verdict"
    # The honest half: raw quantities the caller can reason over.
    assert isinstance(result["headroom_gib"], float)


def test_registry_failure_still_reports_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Host readings do not depend on the VMware registry being readable."""
    fake_psutil(monkeypatch)

    missing = tmp_path / "does-not-exist.vmls"
    monkeypatch.setattr(roster, "inventory_path", lambda: missing)

    result = call(server.host_resources)

    assert result["memory"]["total_gib"] == 32.0
    assert result["volumes"]
    assert result["vm_memory"] == []


def test_tool_is_registered_read_only() -> None:
    """It must be discoverable and must carry the read-only annotation."""
    tool = server.mcp._tool_manager.get_tool("host_resources")
    assert tool is not None
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.destructive_hint is False


def test_tool_takes_no_arguments() -> None:
    """Keeps the contract that a caller cannot pass a path or a volume name."""
    tool = server.mcp._tool_manager.get_tool("host_resources")
    assert tool.parameters.get("properties") == {}