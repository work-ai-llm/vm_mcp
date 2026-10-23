"""vm_mcp — MCP server for a local VMware Workstation lab.

MILESTONE 1 + M3: read-only inspection. Four tools are exposed -- `list_vms`,
`vm_status`, `host_resources` and `guest_health` -- and none of them can change
a VM's state. Mutating tools land later and are gated on the allowlist design
in issue #15.

Where the data comes from
-------------------------
* *Which VMs exist* — `roster.py` reads the VMware Workstation registry
  (`inventory.vmls`), the same file the GUI uses to build its library.
* *Which VMs are running* — one `vmrun -T ws list` call.
* *Per-VM configuration* — the VM's own `.vmx` file, parsed read-only.
* *Host capacity* — `hostinfo.py` reads the host through psutil and starts no
  VMware process at all.
* *Guest liveness* — `health.py` climbs a four-rung ladder (power, Tools
  heartbeat, reachable address, service port) and reports the rung it stopped
  at. See that module for the two lab research findings that shaped it.

The one thing `host_resources` will not do is answer "will another VM fit?".
VMware's per-VM overhead is invisible from outside the hypervisor, so the tool
reports the three raw quantities such an answer would need and leaves the
arithmetic to the caller. See the tool's docstring and `PLAN.md` §4.

Two sources for power state would be tempting and are not used: the registry
has no notion of running state, and vmrun has no notion of existence. Each
supplies the one thing the other cannot.

Two transports, one tool surface
--------------------------------
`--transport stdio` (the default) speaks JSON-RPC over stdin/stdout. The MCP
client launches this process and owns its lifetime. Nothing is reachable.

`--transport http` runs this as a standalone service. The client is handed a
URL and never spawns a process, which is what opencode is configured to use.

Both carry an identical tool surface.

Startup discipline
------------------
Diagnostics go to stderr, never stdout: on stdio, stdout is the JSON-RPC channel
and a stray print corrupts the framing. And nothing blocking happens at import
time, because OpenCode budgets 5000 ms for the tools/list handshake. The
registry is read in `main()`, not at module scope.

Module layout
-------------
This file is `server.py`, not `vm_mcp.py`, and that is deliberate. A module named after
the package it lives in shadows it: running such a module puts its own directory on
`sys.path`, so `from vm_mcp import roster` below resolves to the file instead of the
package and fails with an ImportError that reads like a circular import. It is not one.
Launch with any of:

    python -m vm_mcp                    # shortest
    python -m vm_mcp.server
    vm-mcp                              # console script, from the venv
    python vm_mcp.py                    # repo root; the one to use in a worktree

`__main__.py` exists so the shortest form works. The root `vm_mcp.py` takes the hit this
file avoids -- it is named after the package on purpose and puts `src` ahead of itself to
compensate, which is what lets one venv serve every worktree.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Callable

import psutil
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from vm_mcp import health, hostinfo, power, roster
from vm_mcp.vmrun import (
    STOP_HARD,
    STOP_SOFT,
    VmrunUnavailable,
    list_running_vmx,
    tools_state,
)

__version__ = "0.1.0"

# HTTP settings live here as plain module constants, read by the CLI defaults
# and printed at startup. Deliberately not read from the environment: an
# environment variable is invisible configuration. It gets set in some shell
# profile or launcher, outlives the reason it was set, and the server then
# listens somewhere the config file does not mention.
#
# Loopback is the default because binding 0.0.0.0 would expose a server that can
# inspect a domain controller lab to anything that can route to this machine.
# Widening the bind has to be a deliberate flag.
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8765
DEFAULT_HTTP_PATH = "/mcp"

# `.vmx` is a flat key = "value" file. Keys are matched case-insensitively
# because real files disagree with themselves: `wazuh-4.7.5.vmx` has
# `displayname` and the Ubuntu VM has `displayName`. A case-sensitive pattern
# silently returns nothing for half the lab, which looks exactly like "this VM
# has no name".
_VMX_FIELD_RE = re.compile(r'^\s*([A-Za-z0-9_.]+)\s*=\s*"(.*)"\s*$', re.MULTILINE)

# How much of a .vmx to read. The interesting keys sit at the top; the file can
# run to hundreds of KB with disk descriptors further down.
_VMX_READ_BYTES = 65536

POWER_STOPPED = "stopped"
POWER_RUNNING = "running"
POWER_UNKNOWN = "unknown"

TOOLS_OFFLINE = "undetermined (vm powered off)"

mcp = MCPServer(
    name="vmware",
    version=__version__,
    instructions=(
        "Inspects and controls a local VMware Workstation lab: Windows domain "
        "controllers, servers, and Linux hosts. Call list_vms to see what is "
        "registered and what is running, then vm_status for the detail of one "
        "VM, guest_health to tell a powered-on guest from one that is actually "
        "answering, and host_resources to see what the VMs cost the host. "
        "start_vm, stop_vm and restart_vm change power state; they act on a "
        "single VM named or uuid'd by the caller, never on a path, and never on "
        "more than one machine. A start reports a VM as powered on well before "
        "its guest is usable -- expect roughly 150s more -- so do not treat "
        "'running' as 'ready'. A soft stop_vm and a soft restart_vm return "
        "power_state 'stopping' as soon as the shutdown is in flight and do "
        "not wait for it; confirm the shutdown with the read-only tools "
        "before treating the machine as off, never by re-issuing the stop."
    ),
)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False)

# Powering on changes machine state but destroys nothing, and every read-only
# tool's advice is "start this VM" -- so an agent working within a read-only grant
# is routinely blocked by an accurate annotation. `destructive_hint` is the one
# that carries risk, and it is False here for a real reason: nothing is lost.
MUTATES = ToolAnnotations(read_only_hint=False, destructive_hint=False)

# A hard stop is the power cord. `restart_vm` is marked destructive for the same
# reason even in its graceful form: an unclean shutdown is what damages a guest
# filesystem, and a caller that is told "destructive" and proceeds deliberately
# is behaving exactly as intended.
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True)

# Non-lab VMs are registered on this host too -- a Wazuh SIEM holding 8 GB, among
# them -- and the registry cannot tell a lab member from an appliance. So every
# mutating tool names the resolved VM in its result and in the registry-verified
# path, and the client is expected to gate these by default rather than trust an
# agent to have checked first. See the README's security posture section.


def _norm_path(path: str) -> str:
    """Normalize a .vmx path for comparison between vmrun and the registry.

    Verified: on the M0 host the paths vmrun prints match the registry byte for
    byte. This normalization is insurance against a future release changing
    slash direction or case, not a workaround for an observed mismatch.
    """
    return path.replace("/", "\\").lower()


# `.vmx` `guestos` values are VMware identifiers like `windows9srv-64`,
# `ubuntu-64` or `otherlinux-64`. An agent asked "is this Windows?" would have to
# know that vocabulary to answer, and a wrong guess there is worse than no
# answer.
#
# Matched by prefix, not by substring. "darwin-64" contains "win" and
# "otherlinux-64" contains "linux", so substring matching reports a macOS guest as
# Windows and VMware's own "I cannot classify this" marker as Linux. Order is
# therefore part of the correctness: every entry that is a prefix of another must
# come first.
_OS_FAMILIES: tuple[tuple[str, str], ...] = (
    ("darwin", "macos"),
    ("windows", "windows"),
    ("win", "windows"),
    ("msdos", "dos"),
    ("freebsd", "bsd"),
    ("netbsd", "bsd"),
    ("openbsd", "bsd"),
    ("solaris", "solaris"),
    ("ubuntu", "linux"),
    ("debian", "linux"),
    ("rhel", "linux"),
    ("redhat", "linux"),
    ("centos", "linux"),
    ("fedora", "linux"),
    ("sles", "linux"),
    ("linux", "linux"),
    # VMware's catch-all, reached only after every specific Linux marker. It
    # means "Linux, distro unclassified" and is reported as `linux`: an agent
    # asking "which Linux hosts can I start?" must not silently lose a VM to it.
    # The host's wazuh manager is `otherlinux-64` and is Linux.
    ("otherlinux", "linux"),
    ("other", "other"),
)


def os_family(guestos: str) -> str:
    """Coarse guest OS family for a VMware `guestos` identifier.

    Args:
        guestos: The raw `.vmx` value, e.g. `windows9srv-64`.

    Returns:
        One of `windows`, `linux`, `bsd`, `solaris`, `macos`, `dos`, `other`, or
        `unknown`.

    `otherlinux-64` maps to `linux`, not `other`. It does mean "Linux, distro
    unclassified", and it is tempting to report that as its own thing to avoid
    overstating what we know. The practical cost is worse: an agent enumerating
    Linux hosts would skip the VM entirely, and would be wrong about the lab.
    The unclassified-distro detail is still visible in `guest_os`, so nothing is
    actually lost by answering `linux` here.

    `unknown` is reserved for a value matching no known identifier at all, which
    means we could not read or interpret the field -- not that VMware declined
    to classify the guest.
    """
    folded = guestos.strip().casefold()
    for prefix, family in _OS_FAMILIES:
        if folded.startswith(prefix):
            return family
    return "unknown"


def _read_vmx_fields(vmx_path: str) -> dict[str, str]:
    """Parse the top of a `.vmx` into a lowercase-keyed field dict.

    Returns an empty dict if the file is missing or unreadable; the caller
    decides whether that is fatal.
    """
    try:
        with open(vmx_path, "r", encoding="utf-8", errors="replace") as handle:
            head = handle.read(_VMX_READ_BYTES)
    except OSError:
        return {}

    fields: dict[str, str] = {}
    for key, value in _VMX_FIELD_RE.findall(head):
        fields.setdefault(key.lower(), value.strip())
    return fields


async def _power_states(
    vms: tuple[roster.RegisteredVm, ...],
) -> tuple[dict[str, str], str | None]:
    """Ask VMware which of `vms` are running.

    Returns a mapping of normalized .vmx path to power state, plus the error
    message if VMware could not be reached.

    An unreachable vmrun yields `unknown` for every VM, never `stopped`. The
    distinction matters: "not in the running list" and "could not ask" collapse
    to the same answer otherwise, and during a host fault the server would
    confidently report a powered-on domain controller as off.
    """
    try:
        running = await list_running_vmx()
    except VmrunUnavailable as exc:
        return {_norm_path(vm.vmx): POWER_UNKNOWN for vm in vms}, str(exc)

    running_norm = {_norm_path(path) for path in running}
    return (
        {
            _norm_path(vm.vmx): (
                POWER_RUNNING
                if _norm_path(vm.vmx) in running_norm
                else POWER_STOPPED
            )
            for vm in vms
        },
        None,
    )


@mcp.tool(annotations=READ_ONLY)
async def list_vms() -> dict[str, Any]:
    """List every VM registered with VMware Workstation and whether it is running.

    Takes no arguments. Reads the VMware library registry and asks VMware
    Workstation which VMs are powered on.

    Returns:
        A dict with:
          vms: one entry per registered VM, each with `name` (display name,
              renamable and not unique), `uuid` (stable hardware identifier --
              use this to refer to a VM) and `power_state`.
          counts: total registered, and how many are running.
          observed_via: `vmrun-list` when power state came from VMware, or
              `unavailable` if VMware could not be queried -- in which case
              every `power_state` is `unknown` rather than guessed.

    Note:
        The `.vmx` path is not included. Callers cannot act on a path anyway --
        vm_status resolves identifiers against the registry -- and the Vagrant
        paths run to ~190 characters each, which is most of the payload for
        information nothing can use. `vm_status` returns the path for one VM
        when you need to see where it lives.

    Note:
        Lists what VMware Workstation knows about: VMs registered on this user
        account. A .vmx started directly with vmrun without being registered
        will not appear.
    """
    snapshot = roster.registry()

    if not snapshot.ok:
        return {
            "vms": [],
            "counts": {"total": 0, "running": 0},
            "observed_via": "unavailable",
            "registry_error": snapshot.error,
        }

    states, vmrun_error = await _power_states(snapshot.vms)

    entries = [
        {
            "name": vm.name,
            "uuid": vm.uuid,
            "power_state": states.get(_norm_path(vm.vmx), POWER_UNKNOWN),
        }
        for vm in snapshot.vms
    ]

    return {
        "vms": entries,
        "counts": {
            "total": len(entries),
            "running": sum(
                1 for e in entries if e["power_state"] == POWER_RUNNING
            ),
        },
        "observed_via": "unavailable" if vmrun_error else "vmrun-list",
        **({"vmrun_error": vmrun_error} if vmrun_error else {}),
    }


@mcp.tool(annotations=READ_ONLY)
async def vm_status(uuid: str | None = None, name: str | None = None) -> dict[str, Any]:
    """Report the configuration and power state of one VM.

    Identifies the VM by `uuid` (preferred, unambiguous) or `name` (display
    name, convenient but not unique). Reads the VM's `.vmx` file for CPU and
    memory, and asks VMware Workstation for power state.

    Args:
        uuid: The VM's hardware UUID, as reported by `list_vms`. Spaced or
            undashed forms both work. Survives a display-name rename.
        name: Name or label of the VM. Matched loosely, so `GOAD-DC01` finds a
            VM the registry calls `provider: GOAD-DC01`, and `WindowsServer2019`
            works too. A name matching several VMs is an error listing the
            candidates, not a guess.
            Passing both `uuid` and `name` is allowed when they agree and is an
            error when they do not.

    Returns:
        A dict with:
          name, uuid: identity, from the VMware registry.
          vmx: path to the VM's config file. Included here, but not in
              `list_vms`: for one VM it is worth the characters when you need to
              see where it lives, and for a list it is mostly noise.
          power_state: `running`, `stopped`, or `unknown` if VMware could not be
              queried.
          vcpu: Configured virtual CPU count. A setting, not current CPU load.
          mem_mb: Configured memory in megabytes. A ceiling the VM is allowed to
              use, not current usage -- a stopped VM reports this number while
              using none of it.
          guest_os: The guest operating system identifier as VMware spells it,
              e.g. `windows9srv-64` or `ubuntu-64`. Read from the .vmx because
              the registry's own copy of this is unreliable.
          os_family: Coarse family for `guest_os` -- `windows`, `linux`, `bsd`,
              `solaris`, `macos`, `dos`, `other`, or `unknown`. Present so you can
              ask "is this Windows?" without knowing VMware's vocabulary.
              `otherlinux-64` reports as `linux`, so a Linux enumeration does not
              silently skip it; `unknown` means the field could not be read or
              interpreted, which is not the same as `other`.
          tools_state: VMware Tools state. `running` when the guest agent is
              active, `installed` when present but the VM is off. Says nothing
              about a powered-off guest, so it is reported as undetermined
              rather than guessed.
          vmx_exists: False if the registry lists a VM whose .vmx is missing,
              meaning the registry is stale for that entry.

    On an unresolvable identifier the call fails with `is_error=True` and no
    VMware process is started.
    """
    try:
        vm = roster.resolve(uuid=uuid, name=name)
    except roster.RosterError as exc:
        # Covers UnknownVm, AmbiguousName and IdentifierMismatch. Each already
        # carries a message written for the caller, including what *is*
        # available when the identifier did not match.
        raise ToolError(str(exc)) from exc

    states, vmrun_error = await _power_states((vm,))
    power = states.get(_norm_path(vm.vmx), POWER_UNKNOWN)

    vmx_exists = Path(vm.vmx).is_file()
    fields = _read_vmx_fields(vm.vmx) if vmx_exists else {}

    result: dict[str, Any] = {
        "name": vm.name,
        "uuid": vm.uuid,
        "vmx": vm.vmx,
        "power_state": power,
        "vmx_exists": vmx_exists,
    }

    # Configured resources, reported only when the .vmx was readable. Absent is
    # more honest than zero, which would read as "this VM has no memory".
    for key, field in (("numvcpus", "vcpu"), ("memsize", "mem_mb")):
        raw = fields.get(key)
        if raw is None:
            continue
        try:
            result[field] = int(raw)
        except ValueError:
            result[field] = None

    if "guestos" in fields:
        result["guest_os"] = fields["guestos"]
        result["os_family"] = os_family(fields["guestos"])

    # VMware Tools is only meaningful for a running guest. Calling
    # checkToolsState on a powered-off VM costs 0.65-3.5s to learn `installed`,
    # so the call is skipped and the answer is stated as unavailable.
    if power == POWER_RUNNING:
        try:
            result["tools_state"] = await tools_state(vm.vmx)
        except VmrunUnavailable as exc:
            result["tools_state"] = f"unavailable: {exc}"
    else:
        result["tools_state"] = TOOLS_OFFLINE

    if vmrun_error:
        result["vmrun_error"] = vmrun_error

    return result


@mcp.tool(annotations=READ_ONLY)
async def host_resources() -> dict[str, Any]:
    """Measure this host's CPU, memory and disk, and what the running VMs cost it.

    Takes no arguments and changes nothing: it reads the host, and to know which
    VMs are running it reads the registry and the running set the same way
    `list_vms` does.

    Returns:
        A dict with:
          cpu: Logical and physical core counts, current frequency when the
              platform reports one, and `load_percent` -- busy CPU as a percentage
              across all logical cores, sampled over `sample_window_s`.
          memory: Host total, available, used and used-percent physical memory,
              plus swap. Read `available_gib`, not `used_percent`, to judge
              pressure: Windows counts most of the standby list as available, so a
              host can read 80% used while still holding gigabytes it would
              reclaim.
          volumes: One entry per mounted local volume with total/used/free. A
              volume that cannot be read carries `error` instead of numbers and
              does not affect the others.
          vmware: Resident memory of VMware's host processes right now, summed
              across every VM, largest first. This is the aggregate; `vm_memory`
              carries the per-VM split.
          vm_memory: Per-VM breakdown for running VMs only -- `configured_gib`
              from its `.vmx` against `rss_gib` measured from its host process.
              A stopped VM is absent rather than reported as zero, and `rss_gib`
              is null rather than 0 when no host process could be matched to it.
          headroom_gib: Host available memory minus the configured memory of
              running VMs. Raw subtraction, and the reason this exists.
          uptime: Boot time, uptime in hours, and the host name.

    Note:
        `headroom_gib` is arithmetic, not a verdict, and this tool will not turn it
        into one. VMware reserves host memory outside each guest's configured
        `memsize` -- and reserves it per-VM, so it grows with the number of VMs
        rather than the amount of RAM -- and that overhead is not observable from
        outside the hypervisor. A positive `headroom_gib` therefore does **not**
        mean another VM will fit. A negative one does mean the configured
        allocations already exceed available memory. Its counterpart is
        `rss_gib`: what each VM actually holds on the host right now, which is
        what a VM costs and can sit well below, or above, its `configured_gib`.

    Note:
        `rss_gib` is a host-side measurement, not guest health. It includes
        VMware's per-VM overhead and moves as VMware balloons, pins or pages the
        guest out, so a VM holding far less than its `configured_gib` is not
        thereby a healthy guest -- a guest can be out of memory inside while
        costing the host almost nothing. Guest truth needs guest-side data, which
        is M2's `guest_health`. Read `rss_gib` as "what this VM costs the host
        right now", never as "how the guest is doing".

    Note:
        `load_percent` is absent-as-null when the sample window caught no CPU
        counter ticks, which on Windows happens routinely for windows this short.
        That is "not measured", and is distinct from 0.
    """
    # CPU load needs two samples separated in time. Taking it on the event loop
    # would stall every other tool call for the length of the window, so
    # hostinfo does the reading on a thread.
    sample = await hostinfo.cpu_load()

    memory = hostinfo.host_memory()
    vmware = hostinfo.vmware_process_memory()

    # RSS per running VM, keyed by the .vmx VMware was launched with. This is the
    # attribution `vmware_process_memory` deliberately does not do: it is a
    # different question (what one VM holds) from the aggregate (what all of them
    # hold), and the two are reported separately rather than derived from one
    # another.
    resident = {
        _norm_path(proc["vmx"]): proc["rss_bytes"]
        for proc in hostinfo.vmware_vmx_processes()
    }

    # Which VMs are running, and what each is configured to use. The configured
    # total feeds the headroom figure; the resident map above feeds rss_gib.
    snapshot = roster.registry()
    states, vmrun_error = await _power_states(snapshot.vms)

    per_vm: list[dict[str, Any]] = []
    configured_total = 0
    for vm in snapshot.vms:
        if states.get(_norm_path(vm.vmx)) != POWER_RUNNING:
            continue
        vmx_path = Path(vm.vmx)
        if not vmx_path.is_file():
            continue
        fields = _read_vmx_fields(vm.vmx)
        raw = fields.get("memsize")
        configured = int(raw) if raw and raw.isdigit() else None
        # Null, not zero, when no host process was found: a VM that vmrun calls
        # running but which has no attributable vmware-vmx is "not measured",
        # and 0 would read as "running and holding nothing".
        rss_bytes = resident.get(_norm_path(vm.vmx))
        entry: dict[str, Any] = {
            "name": vm.name,
            "uuid": vm.uuid,
            "configured_gib": round(configured / 1024, 2) if configured else None,
            "rss_gib": round(rss_bytes / hostinfo.GIB, 3) if rss_bytes is not None else None,
        }
        if configured:
            configured_total += configured
        per_vm.append(entry)

    # Sort by what the VM actually holds, falling back to its ceiling when the
    # resident figure is unknown. Sorting by configured would put a VM that is
    # configured large but sitting near idle above the actual memory hog, which
    # is the opposite of what a caller worrying about contention wants first.
    per_vm.sort(
        key=lambda v: v["rss_gib"] if v["rss_gib"] is not None else (v["configured_gib"] or 0),
        reverse=True,
    )

    # memsize is in MiB; hostinfo.GIB is bytes-per-GiB. Both sides are converted
    # from raw units rather than from the already-rounded gib fields above, so a
    # 0.01 GiB rounding error does not leak into the subtraction.
    available_bytes = psutil.virtual_memory().available
    headroom_bytes = available_bytes - configured_total * hostinfo.MIB

    result: dict[str, Any] = {
        "cpu": hostinfo.host_cpu(sample),
        "memory": memory,
        "volumes": hostinfo.host_volumes(),
        "vmware": vmware,
        "vm_memory": per_vm,
        "headroom_gib": round(headroom_bytes / hostinfo.GIB, 2),
        "uptime": hostinfo.host_uptime(),
    }

    if vmrun_error:
        # Without vmrun we cannot tell which VMs are running, so per_vm and
        # headroom would be built from the wrong set -- silently, and reporting
        # zero as though nothing runs. Both are withheld instead.
        result["vm_memory_error"] = vmrun_error
        result.pop("vm_memory")
        result.pop("headroom_gib")

    return result


@mcp.tool(annotations=READ_ONLY)
async def guest_health(
    uuid: str | None = None,
    name: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    """Report whether a guest OS is actually answering, not just powered on.

    Identifies the VM by `uuid` (preferred, unambiguous) or `name` (matched
    loosely), exactly like `vm_status`. The verdict comes from a four-rung
    ladder, and the result names the highest rung an observation was made at:

      power   -- is the VM powered on at all? Not on means `down`.
      tools   -- is the VMware Tools agent heartbeating? A hypervisor-side
                 signal that takes no credentials and separates a booting or
                 frozen guest from one whose OS is actually scheduling.
      address -- discover a guest address the host can route to. Re-done every
                 call, because lab addresses can be DHCP and change per boot.
      service -- open a TCP connection to the guest's service port and close
                 it again. Only this rung answers `up`: a powered-on guest
                 whose services answer nothing is `degraded`.

    Args:
        uuid: The VM's hardware UUID, as reported by `list_vms`.
        name: Name or label of the VM, matched loosely like `vm_status`.
        port: Probe this port instead of the guest-family default
            (Windows: 3389 RDP then 445 SMB; Linux: 22 SSH). Pass it when the
            guest family has no default port or you want a specific service.

    Returns:
        A dict with:
          verdict: `up`, `degraded`, `down`, or `unknown`.
          reached: the highest rung an observation was made at -- `power`,
              `tools`, `address`, or `service`.
          reason: what answered, or why the ladder stopped where it did.
          power_state: `running`, `stopped`, or `unknown` if VMware could not
              be asked.
          tools_state: when observed -- `running`, `installed`, or an
              unavailable note.
          address: the probed guest address, with `address_source` naming
              where it was found (`get-guest-ip` or `neighbor-cache`).
          probes: one entry per port attempt -- `port`, `result`
              (`open`, `refused`, `timeout`, `error`), `ms`.
          rejected_addresses: candidate addresses observed but rejected as not
              reachable from the host. VMware reports the lab's static
              address, which this host has no route to, so this keeps the
              throw-away visible instead of silent.
          vmx_exists: False when the registry lists a VM whose .vmx is gone.

    Note:
        `down` and `unknown` are different answers on purpose. `down` means
        VMware was asked and said the VM is off. `unknown` means VMware could
        not be asked at all -- claiming `down` during a host fault would be a
        confident report that every VM in the lab is off.

    Note:
        No guest credentials are used at any rung, and a probe is a bare TCP
        connect closed immediately: it sends no data and asks for nothing.
    """
    try:
        vm = roster.resolve(uuid=uuid, name=name)
    except roster.RosterError as exc:
        # Covers UnknownVm, AmbiguousName and IdentifierMismatch. Each already
        # carries a message written for the caller, including what *is*
        # available when the identifier did not match.
        raise ToolError(str(exc)) from exc

    if port is not None and not 1 <= port <= 65535:
        # Validation error, passed raw per the tool-error contract.
        raise ToolError(f"port must be between 1 and 65535, got {port}")

    vmx_exists = Path(vm.vmx).is_file()
    fields = _read_vmx_fields(vm.vmx) if vmx_exists else {}
    guestos = fields.get("guestos", "")
    family = os_family(guestos) if guestos else "unknown"

    result = {
        "name": vm.name,
        "uuid": vm.uuid,
        "vmx_exists": vmx_exists,
        **await health.check_health(
            vm.vmx, fields, family=family, port=port
        ),
    }

    if not vmx_exists:
        # A stale registry entry cannot be running, so the ladder ended `down`;
        # the reason *why* it cannot run is the more useful answer.
        result["reason"] = (
            f"{result['reason']} -- and the VM's .vmx is missing from disk"
        )

    return result


def _resolve_for_power(uuid: str | None, name: str | None) -> roster.RegisteredVm:
    """Map a caller identifier to exactly one VM, or fail before anything runs.

    Every mutating tool starts here, and this is the security boundary for all of
    them. A caller never supplies a path -- `vmrun` addresses VMs by absolute
    `.vmx` path, so a tool that accepted one would be an arbitrary-file-primitive
    with a power switch attached. `roster.resolve` returns only paths the VMware
    registry itself lists, which is what makes `stop_vm("../../Windows/System32")`
    a plain error instead of a disaster.

    The `.vmx` existence check is here rather than deeper because a registry is a
    cache written by the GUI: it can name a VM whose `.vmx` was moved or deleted.
    Failing before the command, rather than after, is what keeps a stale entry
    from becoming a confusing vmrun error.
    """
    try:
        vm = roster.resolve(uuid=uuid, name=name)
    except roster.RosterError as exc:
        # Covers UnknownVm, AmbiguousName and IdentifierMismatch. Each already
        # carries a message written for the caller, including what *is*
        # available when the identifier did not match.
        raise ToolError(str(exc)) from exc

    if not Path(vm.vmx).is_file():
        raise ToolError(
            f"{vm.name!r} is registered with VMware but its .vmx is missing: "
            f"{vm.vmx}. The registry is stale for this entry, or the VM was "
            "moved or deleted. Nothing was started. Call list_vms for the "
            "current roster."
        )

    return vm


def _identity(vm: roster.RegisteredVm) -> dict[str, Any]:
    """The name, uuid and path of the VM acted on, echoed back in every result.

    Present in every mutating result, including failures, because the one thing a
    caller must be able to check is *which machine this actually did*. A tool that
    powered something off and returned a bare `{"ok": true}` would leave an agent
    unable to verify it stopped the right VM.
    """
    return {"name": vm.name, "uuid": vm.uuid, "vmx": vm.vmx}


@mcp.tool(annotations=MUTATES)
async def start_vm(uuid: str | None = None, name: str | None = None) -> dict[str, Any]:
    """Power on one VM. Does not wait for the guest to finish booting.

    Identifies the VM by `uuid` (preferred) or `name`, exactly as `vm_status` does,
    and resolves it against the VMware registry. The VM is started with `nogui`,
    so no console window appears.

    Args:
        uuid: The VM's hardware UUID, as reported by `list_vms`.
        name: Name or label of the VM. Matched loosely, so `GOAD-DC01` finds the
            VM the registry calls `provider: GOAD-DC01`.

    Returns:
        A dict with:
          name, uuid, vmx: the VM that was acted on, echoed back so the caller
              can confirm it was the right one.
          power_state: `running` or `stopped`, **read back from `vmrun list`**
              after the start, not taken from the start command's exit code.
          confirmed: True only if that read-back happened. If False, the VM's
              state is unknown and `vmrun_error` says why.
          waited_s: How long the confirmation poll took.

        **`power_state: running` means powered on, not usable.** Measured on this
        host: the start command returns in ~2s while the guest needs a further
        **~156s** before its OS finishes booting and services answer. Nothing in
        this result says the guest is ready, because nothing here has waited to
        find out. To wait for readiness, poll `vm_status` and watch `tools_state`
        go to `running`; on a slow guest expect roughly 150s of that.

        A start that reports `power_state: stopped` with `confirmed: true` is a
        genuine failure -- `vmrun` claimed success and the VM did not appear.

    Note:
        This tool starts a machine. It does not provision it, and it does not
        start anything else on the host.
    """
    vm = _resolve_for_power(uuid, name)
    outcome = await power.start(vm.vmx)
    return {**_identity(vm), **outcome.as_dict()}


@mcp.tool(annotations=DESTRUCTIVE)
async def stop_vm(
    uuid: str | None = None,
    name: str | None = None,
    mode: str = STOP_SOFT,
) -> dict[str, Any]:
    """Request a power-off of one VM. Soft returns at once; hard cuts power.

    Identifies the VM by `uuid` (preferred) or `name` and resolves it against the
    VMware registry.

    Args:
        uuid: The VM's hardware UUID, as reported by `list_vms`.
        name: Name or label of the VM.
        mode: `soft` (default) asks the guest OS to shut itself down, letting it
            unmount filesystems cleanly, and **returns before the shutdown
            finishes** -- see Returns. `hard` cuts power immediately, the
            equivalent of pulling the plug.

    Returns:
        A dict with:
          name, uuid, vmx: the VM that was acted on.
          mode: the mode actually used.
          power_state:
            `stopping` (soft): a graceful shutdown was requested and is being
                carried out in the background. This is NOT an observed state
                and `confirmed` is False. Shutting down typically takes
                30-90s on this lab (measured 26-61s) and a busy Windows guest
                can take longer. Confirm the result before acting on the
                machine: poll vm_status (or list_vms) until `power_state` is
                `stopped`. Re-reading is free; do not re-issue this tool just
                to check state.
            `stopped` (hard): power is verifiably off, read back from
                `vmrun list`. The VM was gone from the hypervisor list when
                this was confirmed.
          confirmed: True only when the state above was actually observed.
          waited_s: How long the call itself waited (small always; a soft
              stop does NOT block on the guest).
          detail: Present when there is something to act on or to wait out.

        If the VM is still running several minutes after a soft request and
        you intend it off, that guest has not shut down -- re-issuing soft
        will not speed that up. `mode: "hard"` cuts power at once; it risks
        guest filesystem damage, so it is never chosen for you: the stop is
        soft until you deliberately ask for hard.

    Note:
        `hard` is destructive and this tool is annotated as such. On a Windows
        domain controller it risks guest filesystem damage. Prefer `soft`
        unless the guest is known to be wedged -- which is exactly the
        situation `guest_health` is for.
    """
    vm = _resolve_for_power(uuid, name)
    outcome = await power.stop(vm.vmx, mode=mode)
    return {**_identity(vm), "mode": mode, **outcome.as_dict()}


@mcp.tool(annotations=DESTRUCTIVE)
async def restart_vm(
    uuid: str | None = None,
    name: str | None = None,
    mode: str = STOP_SOFT,
) -> dict[str, Any]:
    """Restart one VM: stop, then start. The two halves stay separate.

    Identifies the VM by `uuid` (preferred) or `name` and resolves it against the
    VMware registry. Takes the same `mode` as `stop_vm`, applied to the stop.

    Args:
        uuid: The VM's hardware UUID, as reported by `list_vms`.
        name: Name or label of the VM.
        mode: `soft` (default) -- the call issues the graceful shutdown, then
            hands the start half back to you: poll `vm_status` until the VM
            shows `stopped` (typically 30-90s), then call start_vm. This is
            deliberate -- starting a VM that is still shutting down is a state
            this tool refuses to create, and the client enforces a request
            timeout that a slow shutdown would blow anyway.
            `hard` -- fast enough to do the whole cycle in one call: cut
            power (~2s), power back on (~2-3s), return once powered on is
            confirmed.

    Returns:
        A dict with:
          name, uuid, vmx: the VM that was acted on.
          mode: the mode actually used.
          stopped: the `stop_vm` result (`power_state`, `confirmed`,
              `waited_s`, any `detail`). With `mode: "soft"` this is
              `power_state: "stopping"`, `confirmed: false` and a `detail`
              that tells you to call start_vm when vm_status shows stopped.
          started: the `start_vm` result -- present when the VM was verified
              down inside this call (already-off VMs, and confirmed hard
              restarts). **Absent with a soft shutdown in flight**: that is
              the handoff, not an omission.

        When `started` is present, the usual rule applies: `running` means
        powered on, not usable -- expect roughly 150s more before the guest
        answers. That half is reported even when the stop was unremarkable,
        because the case worth seeing is a machine that came back up *without
        having cleanly stopped* and is running on stale state.
    """
    vm = _resolve_for_power(uuid, name)
    stopped, started = await power.restart(vm.vmx, mode=mode)
    payload = {**_identity(vm), "mode": mode, "stopped": stopped.as_dict()}
    if started is not None:
        payload["started"] = started.as_dict()
    return payload


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the command line. Defaults come from the module constants above.

    stdio is the default transport: it opens no port, so a server that can
    inspect a domain controller lab is not sitting on a socket waiting for
    anything.
    """
    parser = argparse.ArgumentParser(
        prog="vm-mcp",
        description="MCP server for a local VMware Workstation lab.",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="stdio: the client launches this process. http: serve and wait to "
        "be connected to. Default: stdio.",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HTTP_HOST,
        help=f"HTTP bind address. Default: {DEFAULT_HTTP_HOST} (loopback only).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_HTTP_PORT,
        help=f"HTTP port. Default: {DEFAULT_HTTP_PORT}.",
    )
    parser.add_argument(
        "--path",
        default=DEFAULT_HTTP_PATH,
        help=f"HTTP endpoint path. Default: {DEFAULT_HTTP_PATH}.",
    )
    return parser.parse_args(argv)


def http_banner(host: str, port: int, path: str) -> str:
    """The startup message for HTTP mode: settings, URL, and a security warning.

    Printed on every HTTP start. The warning is no longer hypothetical -- since
    M2 this endpoint can power off a domain controller, and anyone who can reach
    the socket can ask it to. Worth saying out loud on every launch rather than
    once in a README.
    """
    if host in ("127.0.0.1", "localhost", "::1"):
        exposure = "bound to loopback, so only processes on this machine can reach it"
    else:
        exposure = (
            f"bound to {host}, which is reachable by anything that can route to "
            "this machine"
        )

    return "\n".join(
        [
            f"vm_mcp {__version__} — HTTP transport",
            "",
            f"  host      : {host}",
            f"  port      : {port}",
            f"  path      : {path}",
            f"  url       : http://{host}:{port}{path}",
            "",
            "  SECURITY: no authentication is established on this endpoint. "
            "There is no token,",
            "  no TLS and no client identity check, so anything that can reach "
            "the socket can call",
            "  every tool this server exposes -- including stop_vm and "
            "restart_vm, which can",
            "  power off a domain controller and, in hard mode, risk guest "
            "filesystem damage.",
            f"  Currently {exposure}. Authentication is a tracked follow-up and "
            "is not done yet;",
            "  gate the mutating tools client-side until it is.",
            "",
        ]
    )


def _port_is_free(host: str, port: int) -> bool:
    """True if nothing is already listening on host:port.

    A second server on the same port does not fail loudly; the OS hands the
    socket to the first process and the second dies with a bind error that
    scrolls past in a launcher window. Checking up front lets it explain itself.
    """
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError:
            return False
    return True


_INTERRUPTED = "vm_mcp: interrupted -- shut down cleanly"


def _run_transport(run: Callable[[], None]) -> None:
    """Run a transport, turning Ctrl+C into a clean stop instead of a traceback.

    Ctrl+C is not a failure, but by default it looks like one. uvicorn captures
    SIGINT to shut down gracefully and then re-raises it, so a KeyboardInterrupt
    arrives here -- after the server has already stopped and reported
    "Application shutdown complete". Anyio re-raises it too. Left uncaught, the
    interpreter prints a CancelledError traceback, then "During handling of the
    above exception, another exception occurred", then KeyboardInterrupt, and
    exits with the Ctrl+C status code. None of that is true: the shutdown
    succeeded. So the interrupt is caught and reported as what it is.
    """
    try:
        run()
    except KeyboardInterrupt:
        print(_INTERRUPTED, file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    # Read the registry once here, so a broken one is reported at boot instead of
    # on the first tool call, and so the banner can say what was found. Tools
    # re-read per call; this is a health check, not a cache.
    snapshot = roster.registry()
    if snapshot.ok:
        print(
            f"vm_mcp: VMware registry: {len(snapshot.vms)} VMs registered",
            file=sys.stderr,
            flush=True,
        )
    else:
        print(
            f"vm_mcp: VMware registry unavailable: {snapshot.error}",
            file=sys.stderr,
            flush=True,
        )

    if args.transport == "http":
        if not _port_is_free(args.host, args.port):
            print(
                f"vm_mcp {__version__}: {args.host}:{args.port} is already in use. "
                "A server may already be running here -- if so, that is fine, "
                "just connect to it. Otherwise pass --port to pick another.",
                file=sys.stderr,
                flush=True,
            )
            raise SystemExit(1)

        # stderr, never stdout. See the module docstring.
        print(http_banner(args.host, args.port, args.path), file=sys.stderr, flush=True)
        _run_transport(
            lambda: mcp.run(
                transport="streamable-http",
                host=args.host,
                port=args.port,
                streamable_http_path=args.path,
            )
        )
        return

    print(f"vm_mcp {__version__} starting on stdio", file=sys.stderr, flush=True)
    _run_transport(mcp.run)


if __name__ == "__main__":
    main()