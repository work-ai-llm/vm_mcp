"""vm_mcp — MCP server for a local VMware Workstation lab.

MILESTONE 1: read-only inspection. Three tools are exposed — `list_vms`,
`vm_status` and `host_resources` — and none of them can change a VM's state.
Mutating tools land later and are gated on the allowlist design in issue #15.

Where the data comes from
-------------------------
* *Which VMs exist* — `roster.py` reads the VMware Workstation registry
  (`inventory.vmls`), the same file the GUI uses to build its library.
* *Which VMs are running* — one `vmrun -T ws list` call.
* *Per-VM configuration* — the VM's own `.vmx` file, parsed read-only.
* *Host capacity* — `hostinfo.py` reads the host through psutil and starts no
  VMware process at all.

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
from typing import Any

import psutil
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from vm_mcp import hostinfo, roster
from vm_mcp.vmrun import VmrunUnavailable, list_running_vmx, tools_state

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
        "Inspects a local VMware Workstation lab: Windows domain controllers, "
        "servers, and Linux hosts. Call list_vms to see what is registered and "
        "what is running, then vm_status for the detail of one VM. This "
        "milestone is read-only; no tool changes a VM's state."
    ),
)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False)


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
              across every VM, largest first. Aggregate only -- it is not broken
              down per VM.
          vm_memory: Per-VM breakdown for running VMs only -- `configured_gib`
              from its `.vmx`. A stopped VM is absent rather than reported as
              zero.
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
        allocations already exceed available memory. What a VM actually holds on
        the host is only visible in aggregate, as `vmware`, and cannot be
        attributed to individual VMs from here.

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

    # Which VMs are running, and what each is configured to use. Both are needed
    # for the headroom figure and neither can come from vmware_process_memory:
    # that sums RSS across processes with no mapping back to a VM.
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
        entry: dict[str, Any] = {
            "name": vm.name,
            "uuid": vm.uuid,
            "configured_gib": round(configured / 1024, 2) if configured else None,
        }
        if configured:
            configured_total += configured
        per_vm.append(entry)

    per_vm.sort(key=lambda v: v["configured_gib"] or 0, reverse=True)

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

    Printed on every HTTP start. There is no authentication on this transport,
    so anyone who can reach the socket can call every tool on it -- and the tool
    surface is going to include power-off. Worth saying when it becomes true.
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
            "  every tool this server exposes. The tools shipped so far are "
            "read-only, but once the",
            "  mutating tools land, this endpoint will be able to power off a "
            "domain controller and",
            f"  anyone who can reach it can ask for that. Currently {exposure}.",
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
        mcp.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            streamable_http_path=args.path,
        )
        return

    print(f"vm_mcp {__version__} starting on stdio", file=sys.stderr, flush=True)
    mcp.run()


if __name__ == "__main__":
    main()