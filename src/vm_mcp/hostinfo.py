"""Host CPU, memory and disk measurement for `host_resources`.

Separated from `server.py` because it is the one part of the tool surface that
touches no VMware component at all: it reads the host through `psutil` and never
starts `vmrun`. That makes it the cheapest tool in the set and the only one whose
answers are safe to cache per call.

What this module refuses to do
------------------------------
It does not answer "will another VM fit?". VMware's per-VM overhead -- the host
memory, CPU and disk it reserves outside the guest's configured `memsize` -- is
not observable from outside the hypervisor, so any such number would be a guess
presented as a measurement. What it reports instead is the three raw quantities
an answer would have to be built from: host memory available, the sum of
configured memory for VMs that are actually running, and the resident size of
those VMs' processes. A caller that wants to reason about headroom has all of it;
this module declines to launder it into a verdict. See `PLAN.md` §4.

Two platform facts are baked in, both measured on the M1 host:

1. **Windows CPU counters tick at ~15.6 ms.** A sample window short enough to feel
   instant can catch *no* ticks, which makes total-minus-idle come out as 0/0.
   That is reported as `unknown`, never as 0% or 100%.
2. **`scputimes` fields differ by platform.** Windows has user, system, idle,
   interrupt, dpc; Linux adds nice, iowait, irq, softirq, steal. Busy time is
   therefore derived as total-minus-idle over whichever fields the platform
   actually has, instead of naming a Linux-only field that raises `AttributeError`
   on Windows.

Sampling blocks, so every entry point here is async and hands the work to a
thread. `psutil.cpu_percent(interval=0.5)` in the middle of an event loop would
stall every other tool call for half a second.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Any, Callable

import psutil

__all__ = [
    "CpuSample",
    "HostError",
    "cpu_load",
    "host_cpu",
    "host_memory",
    "host_uptime",
    "host_volumes",
    "sample_cpu",
    "vmware_process_memory",
]

# Long enough to catch several Windows counter ticks, short enough that a tool
# call does not feel stuck. 0.25s is the floor; below it the "no ticks at all"
# case in the module docstring becomes common rather than rare.
CPU_SAMPLE_WINDOW = 0.25

# Bytes per GiB, as psutil reports everything in bytes.
GIB = 1024**3
MIB = 1024**2


class HostError(Exception):
    """Host measurement failed.

    Raised per-source rather than for the whole tool: an unreadable disk must not
    cost the caller the CPU and memory readings that succeeded.
    """


@dataclass(frozen=True)
class CpuSample:
    """One CPU load observation.

    Attributes:
        percent: Busy CPU as a percentage of all logical CPUs, or None if the
            sample window caught no counter ticks. None means "not measured",
            which is different from 0.
        window_s: How long the sample actually took.
        busy_s: CPU-seconds consumed across all logical CPUs in the window.
        idle_s: CPU-seconds idle across all logical CPUs in the window.
    """

    percent: float | None
    window_s: float
    busy_s: float
    idle_s: float


def _busy_from_times(before: Any, after: Any) -> tuple[float, float]:
    """Busy and idle CPU-seconds between two `cpu_times()` readings.

    Derived as total-minus-idle so it works on any platform's field set. Returns
    `(busy, idle)`; both are 0.0 when the platform reports no comparable fields.
    """
    # Field discovery goes through `dir()` rather than `_asdict()` or `vars()`.
    # psutil returns a namedtuple, which has `_asdict()` but an empty `__dict__`;
    # a plain object holding its fields as class attributes has the opposite
    # problem. `dir()` finds the counters on either, which is all this needs --
    # the names are what matter, not the container.
    deltas = {
        key: getattr(after, key) - getattr(before, key)
        for key in dir(after)
        if not key.startswith("_") and not callable(getattr(after, key))
        and hasattr(before, key)
    }
    idle = max(0.0, deltas.pop("idle", 0.0))
    # `steal` and `softirq` are time the guest lost to the hypervisor, not time
    # this host did useful work. Counting them as busy would report a fully
    # loaded host on an otherwise idle one.
    for foreign in ("steal",):
        if foreign in deltas:
            idle += max(0.0, deltas[foreign])
            deltas.pop(foreign)
    busy = max(0.0, sum(deltas.values()))
    return busy, idle


def sample_cpu(
    window_s: float = CPU_SAMPLE_WINDOW,
    *,
    times: Callable[[], Any] = psutil.cpu_times,
    sleep: Callable[[float], None] = time.sleep,
) -> CpuSample:
    """Measure CPU load over `window_s` by sampling `cpu_times` twice.

    Args:
        window_s: Gap between the two samples.
        times: Injection point for `cpu_times`, so tests need no real sleep.
        sleep: Injection point for the sleep between samples.

    Returns:
        A `CpuSample`. `percent` is None when the window caught no ticks, which on
        Windows happens routinely for short windows and must not be reported as
        either 0% or 100%.
    """
    before = times()
    start = time.monotonic()
    sleep(window_s)
    after = times()
    elapsed = time.monotonic() - start

    busy, idle = _busy_from_times(before, after)
    total = busy + idle

    return CpuSample(
        percent=round(100.0 * busy / total, 1) if total > 0 else None,
        window_s=round(elapsed, 3),
        busy_s=round(busy, 3),
        idle_s=round(idle, 3),
    )


async def cpu_load(window_s: float = CPU_SAMPLE_WINDOW) -> CpuSample:
    """Async wrapper around `sample_cpu`.

    The sleep between samples is the reason this is off the event loop: a blocking
    read here would freeze every concurrent tool call for the length of the
    window.
    """
    return await asyncio.to_thread(sample_cpu, window_s)


def host_cpu(sample: CpuSample | None = None) -> dict[str, Any]:
    """CPU inventory plus one load observation.

    Logical and physical counts are static facts. `frequency_mhz` is absent rather
    than null when the platform or power policy will not report it -- psutil
    returns None for current on some machines, and a null field reads as a
    measurement that failed instead of one that does not exist.
    """
    info: dict[str, Any] = {
        "logical_cores": psutil.cpu_count(logical=True),
        "physical_cores": psutil.cpu_count(logical=False),
    }

    try:
        freq = psutil.cpu_freq()
    except (NotImplementedError, OSError):
        freq = None
    if freq is not None and freq.current:
        info["frequency_mhz"] = round(freq.current, 1)

    if sample is not None:
        info["load_percent"] = sample.percent
        info["sample_window_s"] = sample.window_s

    return info


def host_memory() -> dict[str, Any]:
    """Host physical memory and swap, as measured.

    `available` is reported alongside `percent` because the two disagree in a way
    that matters: Windows counts most of the standby list as available, so a host
    can read 80% used while still having gigabytes of genuinely reclaimable
    memory. `percent` alone would overstate the pressure.
    """
    virtual = psutil.virtual_memory()
    swap = psutil.swap_memory()

    return {
        "total_gib": round(virtual.total / GIB, 2),
        "available_gib": round(virtual.available / GIB, 2),
        "used_gib": round((virtual.total - virtual.available) / GIB, 2),
        "used_percent": virtual.percent,
        "swap_total_gib": round(swap.total / GIB, 2),
        "swap_used_gib": round(swap.used / GIB, 2),
    }


def host_volumes() -> list[dict[str, Any]]:
    """Fixed-disk usage for every mounted volume.

    One unreadable volume does not fail the call. On the M1 host `E:\\` raises
    `WinError 21` from `disk_usage` -- a stale or virtual drive letter -- and
    losing the C: and D: readings because of it would be a worse answer than
    reporting the failure alongside the volumes that did answer.

    Only fixed and removable local volumes are reported; the ones psutil would
    need `all=True` to see are network and CD-ROM mounts, where `disk_usage`
    either blocks on an unreachable share or returns the share's capacity rather
    than this host's.
    """
    volumes: list[dict[str, Any]] = []

    for part in psutil.disk_partitions(all=False):
        entry: dict[str, Any] = {
            "device": part.device,
            "mountpoint": part.mountpoint,
            "fstype": part.fstype,
            "removable": "removable" in (part.opts or ""),
        }
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (OSError, PermissionError) as exc:
            entry["error"] = str(exc)
        else:
            entry["total_gib"] = round(usage.total / GIB, 2)
            entry["used_gib"] = round(usage.used / GIB, 2)
            entry["free_gib"] = round(usage.free / GIB, 2)
            entry["used_percent"] = usage.percent
        volumes.append(entry)

    return volumes


def vmware_process_memory(
    names: tuple[str, ...] = ("vmware-vmx.exe", "vmware.exe"),
) -> dict[str, Any]:
    """Resident memory of VMware's own processes.

    This is the measured counterpart to a VM's *configured* `memsize`: the `.vmx`
    says what the guest is allowed to use, this says what is actually resident on
    the host right now. Both are reported by `host_resources` so a caller can see
    them disagree -- a VM configured with 8 GiB reserving 6 GiB is a real and
    common gap, and hiding either number would make the headroom arithmetic
    unfalsifiable.

    Per-process detail is limited to the largest few. The full list is an
    implementation detail of how VMware forks workers, and it moves between calls.
    """
    total_rss = 0
    vmware_vmx_rss = 0
    count = 0
    per_process: list[dict[str, Any]] = []
    inaccessible = 0

    for proc in psutil.process_iter(["name", "memory_info"]):
        try:
            name = (proc.info["name"] or "").lower()
            if name not in names:
                continue
            rss = proc.info["memory_info"].rss
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # A VM process can be torn down mid-iteration; it is a race, not a
            # fault, and the next call will not see it either.
            inaccessible += 1
            continue

        total_rss += rss
        count += 1
        if name == "vmware-vmx.exe":
            vmware_vmx_rss += rss
        per_process.append({"name": name, "rss_gib": round(rss / GIB, 3)})

    per_process.sort(key=lambda p: p["rss_gib"], reverse=True)

    result: dict[str, Any] = {
        "process_count": count,
        "total_rss_gib": round(total_rss / GIB, 2),
        "vmware_vmx_rss_gib": round(vmware_vmx_rss / GIB, 2),
    }
    if per_process:
        result["largest"] = per_process[:5]
    if inaccessible:
        result["inaccessible_processes"] = inaccessible

    return result


def host_uptime() -> dict[str, Any]:
    """Boot time and uptime.

    Relevant to `host_resources` because a host that has been up for a week
    accumulates the handle and cache pressure that makes VMware slow, and an
    agent deciding whether to start another VM has no other way to see it.
    """
    boot = psutil.boot_time()
    return {
        "boot_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(boot)),
        "uptime_hours": round((time.time() - boot) / 3600, 1),
        "host_name": os.environ.get("COMPUTERNAME") or None,
    }