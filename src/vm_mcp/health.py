"""The `guest_health` ladder: is a powered-on guest actually answering?

The tool answers "is this machine up and working, or is it frozen and in need
of a power-cycle?" — which is the reason the project exists. The verdict model
comes from issue #12 (M3): a guest that is powered on but not answering is
`degraded`, never `up`, and "could not ask" is its own answer rather than a
verdict-shaped guess.

The ladder is ordered by cost and by how much each observation actually
proves. Every rung was verified against live VMware Workstation before being
coded:

1. power    -- is the VM in `vmrun list`? No network, no credentials.
2. tools    -- does VMware Tools report `running`? CheckToolsState answers from
               the hypervisor's view of the `vmtoolsd` heartbeat, so a guest
               whose OS stopped scheduling stops reporting `running`. That is
               the frozen-vs-booting discriminator that needs no credentials
               and works for every VM regardless of guest networking.
3. address  -- find a guest address the host can actually route to.
4. service  -- open a TCP connection to the guest's service port. A raw-socket
               connect measured ~90 ms; the PowerShell alternative costs
               12-14 s per try (research blocker B7), which would make one
               call of several rungs unusable.

Three findings from the lab research shaped decisions here, and each of them
is a "provably wrong easy answer" avoided:

* `getGuestIPAddress` output is a *candidate*, never a probe target (B2). It
  reported the unroutable static GOAD address for one VM and the
  host-reachable bridged DHCP address for another, so every candidate is
  validated against the host's own on-link subnets. The same MAC address the
  `.vmx` declares for each adapter also appears in the Windows neighbor cache,
  and cache entries matched by MAC are the credential-free fallback that finds
  the bridged, DHCP-per-boot address when vmrun reports only the static one.
* A guest op is not a readiness gate (B6): `listProcessesInGuest` answered
  t+2.4 s into a boot that physically needed 156 s, meaning the ladder must
  not take a successful vmrun guest call as "the guest is up". The only rung
  that can prove up-ness is a service port answering, so that is what `up`
  requires.
* ICMP is not a probe of anything here: 9 minutes of `Test-Connection` loss
  against a guest that was demonstrably alive. TCP connect is both more
  informative (a real service is listening) and as cheap.

`down` (not powered on) and `unknown` (could not ask) are deliberately
different verdicts. Collapsing them turns a host fault into "every domain
controller is powered off", or a misconfigured network into "broken lab",
depending on which way it collapses.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import psutil

from vm_mcp.vmrun import (
    VmrunUnavailable,
    get_guest_ip,
    list_running_vmx,
    tools_state,
)

__all__ = [
    "VERDICT_UP",
    "VERDICT_DEGRADED",
    "VERDICT_DOWN",
    "VERDICT_UNKNOWN",
    "REACHED_POWER",
    "REACHED_TOOLS",
    "REACHED_ADDRESS",
    "REACHED_SERVICE",
    "DEFAULT_PORTS",
    "PROBE_TIMEOUT",
    "ProbeOutcome",
    "Discovery",
    "tcp_probe",
    "host_subnets",
    "neighbor_entries",
    "vmx_macs",
    "discover_address",
    "check_health",
]

logger = logging.getLogger(__name__)

VERDICT_UP = "up"
VERDICT_DEGRADED = "degraded"
VERDICT_DOWN = "down"
VERDICT_UNKNOWN = "unknown"

# The ladder rungs, as reported in `reached`. Each names the highest rung an
# observation was successfully made at, so a caller can tell "it stopped at
# the tools rung" from "it stopped at the address rung" without parsing the
# reason string.
REACHED_POWER = "power"
REACHED_TOOLS = "tools"
REACHED_ADDRESS = "address"
REACHED_SERVICE = "service"

# Service ports by guest-OS family, in probe order. Windows guests run many
# listeners; RDP (3389) is what an agent would use to work on the machine and
# SMB (445) is what a domain server cannot be without -- both were verified
# open on a live GOAD DC from this host, in single-digit milliseconds. SSH for
# the Linux guests. A family with no entry gets no probe and the result says
# so explicitly rather than probing a made-up port.
DEFAULT_PORTS: dict[str, tuple[int, ...]] = {
    "windows": (3389, 445),
    "linux": (22,),
    "macos": (5900,),
    "bsd": (22,),
    "solaris": (22,),
}

# Per-attempt ceiling. Open and refused answer in single-digit milliseconds on
# the host LAN; the timeout exists for a port that drops instead of answering,
# where the OS would wait out its own multi-second SYN retry schedule.
PROBE_TIMEOUT = 2.0

# Socket errnos that mean "the connect attempt timed out": WSAETIMEDOUT on
# Windows and ETIMEDOUT elsewhere. OSError carrying another errno is some
# other failure and keeps the `error` label.
_TIMED_OUT_ERRNOS = {10060, 110}


def _norm(path: str) -> str:
    """Normalize a .vmx path for comparison, same rule as server._norm_path.

    Kept local rather than imported so health does not depend on server, the
    direction of dependency staying downward.
    """
    return path.replace("/", "\\").lower()


@dataclass(frozen=True)
class ProbeOutcome:
    """One TCP connect attempt.

    Attributes:
        result: `open` (connected and closed again), `refused` (a RST came
            back: the guest's IP stack is alive and *that port* is closed --
            a positive observation about the guest, not a failure), `timeout`
            (no answer in time), or `error` (unroutable, no route, etc.).
        ms: Wall time of the attempt, minimum 1.
        detail: The exception text, populated for `error`.
    """

    result: str
    ms: int
    detail: str | None = None


@dataclass(frozen=True)
class Discovery:
    """Candidate guest addresses after reachability validation.

    Attributes:
        reachable: Addresses on a host subnet, in discovery order.
        rejected: Addresses observed but not reachable from the host,
            reported so the caller can see *what* was thrown away (which is
            how B2 stops being a silent guessing game).
        source: Where `reachable[0]` came from: `get-guest-ip`, or
            `neighbor-cache` when only the MAC-matched cache found one, or
            `none`.
    """

    reachable: list[str]
    rejected: list[str]
    source: str


def _ms(t0: float) -> int:
    return max(1, round((time.perf_counter() - t0) * 1000))


async def tcp_probe(
    ip: str, port: int, *, timeout: float = PROBE_TIMEOUT
) -> ProbeOutcome:
    """Attempt one TCP connect and classify the answer.

    Anything that completes a handshake is `open`; the connection is closed
    again immediately, so the probe sends no data and asks for nothing -- it
    is the network equivalent of knocking and walking away. A refused connect
    is kept distinct from a timeout on purpose: an RST is the guest's own
    stack proving it is alive, which, while not `up`, is worth knowing that a
    service is simply not listening rather than that nothing answered.
    """
    t0 = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout
        )
    except ConnectionRefusedError:
        return ProbeOutcome("refused", _ms(t0))
    except asyncio.TimeoutError:
        return ProbeOutcome("timeout", _ms(t0))
    except OSError as exc:
        if getattr(exc, "errno", None) in _TIMED_OUT_ERRNOS or getattr(
            exc, "winerror", None
        ) in _TIMED_OUT_ERRNOS:
            return ProbeOutcome("timeout", _ms(t0))
        return ProbeOutcome("error", _ms(t0), str(exc))

    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except asyncio.TimeoutError:
        pass
    except OSError:
        pass
    return ProbeOutcome("open", _ms(t0))


def host_subnets() -> list["ipaddress.IPv4Network"]:
    """The host's own on-link IPv4 subnets, loopback and link-local excluded.

    Reachability means "the host has an interface on this prefix", which is
    the condition under which an ARP-assisted TCP connect has a chance of
    succeeding in reasonable time. A candidate outside every prefix -- like
    the lab's static 192.168.230.x, for which the host's VMnet1 adapter does
    not exist -- is rejected here rather than paid for later in a SYN timeout.
    """
    subnets: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            if not addr.address or not addr.netmask:
                continue
            try:
                net = ipaddress.ip_network(
                    f"{addr.address}/{addr.netmask}", strict=False
                )
            except ValueError:
                continue
            if net.is_loopback or net.is_link_local or net.is_multicast:
                continue
            if str(net) not in seen:
                seen.add(str(net))
                subnets.append(net)
    return subnets


_ARP_LINE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})"
)


def neighbor_entries() -> dict[str, str]:
    """MAC -> IP pairs from the Windows neighbor cache (`arp -a`).

    Parsed from the numeric columns only. The header lines are localized on
    this host and render as noise on its cp866 console, but the data lines are
    `IP  MAC  type`, which no locale touches. Multicast and broadcast entries
    parse too and are harmless: they will simply never match a VM's declared
    MAC.

    Raises:
        OSError, from the subprocess call, so the caller decides what
        "could not read the cache" means; to this module it means the
        fallback source is simply unavailable.
    """
    proc = subprocess.run(["arp", "-a"], capture_output=True, timeout=10)
    text = proc.stdout.decode("utf-8", "replace")
    entries: dict[str, str] = {}
    for match in _ARP_LINE.finditer(text):
        ip, mac = match.group(1), match.group(2)
        entries.setdefault(mac.replace("-", ":").lower(), ip)
    return entries


_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def vmx_macs(fields: Mapping[str, str]) -> list[str]:
    """The NIC MACs a parsed `.vmx` declares, normalized to colon-lowercase.

    Both `generatedAddress` and `address` are read because which one is
    populated depends on the adapter's addressType. Disabled NICs are included
    deliberately: `startConnected = FALSE` describes the adapter that is
    exactly the one *absent* from the neighbor cache, and its MAC matching
    nothing is the observation that confirms the adapter is not connected.
    Malformed strings are dropped rather than normalized into a guess.
    """
    macs: list[str] = []
    for n in range(10):
        if fields.get(f"ethernet{n}.present", "").strip().lower() != "true":
            continue
        mac = fields.get(f"ethernet{n}.generatedaddress") or fields.get(
            f"ethernet{n}.address"
        )
        if not mac:
            continue
        normalized = mac.replace("-", ":").strip().lower()
        if _MAC_RE.match(normalized):
            macs.append(normalized)
    return macs


def _on_host_subnet(ip: str, subnets: list["ipaddress.IPv4Network"]) -> bool:
    """True if `ip` parses as a unicast IPv4 address on one of `subnets`."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    ):
        return False
    return any(addr in net for net in subnets)


async def discover_address(
    vmx: str, fields: Mapping[str, str], *, executable: Path | None = None
) -> Discovery:
    """Find a guest address the host can route to, using no guest credentials.

    Two candidate sources, both credential-free:

    * `getGuestIPAddress` -- vmrun's answer, validated against the host's own
      subnets before it is trusted (see the module docstring on B2).
    * the Windows neighbor cache matched by `.vmx`-declared MAC -- what finds
      the bridged, DHCP-per-boot address in the lab the research measured,
      where vmrun instead reports the unroutable static one.

    Discovery happens on every call, not once. DHCP addresses change between
    boots; keeping the one that worked last time would, after the next boot,
    spend the probe budget knocking on a door that may be another machine's.

    Raises:
        Nothing for the expected failures; each source that cannot be asked
        is skipped and the other gets a turn.
    """
    subnets = host_subnets()

    reachable: list[str] = []
    rejected: list[str] = []
    source = "none"

    try:
        vmrun_ip = await get_guest_ip(vmx, executable=executable)
    except VmrunUnavailable as exc:
        logger.debug("getGuestIPAddress unavailable: %s", exc)
        vmrun_ip = None

    if vmrun_ip:
        if _on_host_subnet(vmrun_ip, subnets):
            reachable.append(vmrun_ip)
            source = "get-guest-ip"
        else:
            rejected.append(vmrun_ip)

    if not reachable:
        try:
            cache = await asyncio.to_thread(neighbor_entries)
        except OSError as exc:
            logger.debug("neighbor cache unavailable: %s", exc)
            cache = {}
        declared = set(vmx_macs(fields))
        for mac, ip in cache.items():
            if mac not in declared:
                continue
            if _on_host_subnet(ip, subnets) and ip not in reachable:
                reachable.append(ip)
                source = "neighbor-cache"
                break
            if ip not in rejected:
                rejected.append(ip)

    return Discovery(reachable=reachable, rejected=rejected, source=source)


async def check_health(
    vmx: str,
    fields: Mapping[str, str],
    *,
    family: str = "unknown",
    port: int | None = None,
    probe_timeout: float = PROBE_TIMEOUT,
    executable: Path | None = None,
) -> dict[str, Any]:
    """Run the four-rung ladder for one VM and report verdict + evidence.

    Args:
        vmx: The VM's `.vmx` path, exactly as the registry lists it.
        fields: The parsed `.vmx` fields, used for NIC MACs.
        family: The coarse guest-OS family, which selects the default service
            ports. The mapping lives here but `family` itself is computed in
            server.py, where `os_family` already exists.
        port: Probe this port instead of the family defaults. Given a port,
            only that one is tried.
        probe_timeout: Per-attempt connect ceiling.
        executable: vmrun override, for tests.

    Returns:
        A dict of observations plus the three fields the caller cares about:

          verdict -- `up` (a service port answered), `degraded` (powered on
              but the ladder stopped short of a service answering), `down`
              (not powered on), or `unknown` (VMware could not be asked).
          reached -- the highest rung an observation was successfully made at
              (`power`, `tools`, `address`, `service`), so the caller can see
              how far the ladder got and not just the verdict.
          reason -- what answered, or why the ladder stopped.

        Informational fields are present only when observed, per the M1 rule
        that absent beats a filler value: `tools_state`, `address`,
        `address_source`, `rejected_addresses`, `probes`.

    Never raises for the expected failures: every "could not ask" becomes a
    value with an explanation, because the model must never be left to choose
    between an exception it cannot interpret and a verdict it cannot trust.
    """
    result: dict[str, Any] = {
        "verdict": VERDICT_UNKNOWN,
        "reached": None,
        "reason": "",
        "power_state": "unknown",
    }

    # Rung 1: power. One `vmrun list` answers for the whole roster, so this
    # costs the same whether the lab is one VM or eight.
    try:
        running = await list_running_vmx(executable=executable)
    except VmrunUnavailable as exc:
        result["reason"] = str(exc)
        return result

    on = _norm(vmx) in {_norm(p) for p in running}
    result["reached"] = REACHED_POWER
    result["power_state"] = "running" if on else "stopped"

    if not on:
        # `down`, not `unknown`: vmrun answered, and the answer is "off".
        result["verdict"] = VERDICT_DOWN
        result["reason"] = "not in vmrun's running list"
        return result

    # Rung 2: the Tools heartbeat. checkToolsState is skipped for a powered-off
    # VM (answers `installed` after seconds of nothing) but matters only here.
    try:
        tools = await tools_state(vmx, executable=executable)
    except VmrunUnavailable as exc:
        result["verdict"] = VERDICT_DEGRADED
        result["reached"] = REACHED_TOOLS
        result["reason"] = (
            f"powered on, but VMware Tools state could not be asked: {exc}"
        )
        return result

    result["tools_state"] = tools
    if tools != "running":
        result["verdict"] = VERDICT_DEGRADED
        result["reached"] = REACHED_TOOLS
        result["reason"] = (
            f"powered on, but VMware Tools reports '{tools}' -- the guest is "
            "booting or its agent is not answering the hypervisor"
        )
        return result

    if port is not None:
        ports: tuple[int, ...] = (port,)
    else:
        ports = DEFAULT_PORTS.get(family, ())
    if not ports:
        result["verdict"] = VERDICT_DEGRADED
        result["reached"] = REACHED_TOOLS
        result["reason"] = (
            f"powered on with VMware Tools running, but no default service "
            f"port is known for a '{family}' guest -- pass port to probe one"
        )
        return result

    # Rung 3: reach a live guest address. This is per-call by design: DHCP
    # hands out a different address per boot, so a cached address eventually
    # knocks on the wrong door.
    discovery = await discover_address(vmx, fields, executable=executable)
    if discovery.rejected:
        result["rejected_addresses"] = discovery.rejected
    if not discovery.reachable:
        result["verdict"] = VERDICT_DEGRADED
        result["reached"] = REACHED_TOOLS
        if discovery.rejected:
            detail = (
                "the candidate guest address "
                f"{discovery.rejected[0]} is not on any host subnet"
            )
        else:
            detail = "neither getGuestIPAddress nor the neighbor cache offered a reachable address"
        result["reason"] = (
            f"powered on with VMware Tools running, but {detail}"
        )
        return result

    target = discovery.reachable[0]
    result["address"] = target
    result["address_source"] = discovery.source
    result["reached"] = REACHED_ADDRESS

    # Rung 4: does a service answer? Ports are tried in order and the ladder
    # stops at the first `open`; a refusal does not end the ladder, because a
    # closed RDP on a machine with live SMB is still an up machine.
    probes: list[dict[str, Any]] = []
    for candidate_port in ports:
        outcome = await tcp_probe(target, candidate_port, timeout=probe_timeout)
        probes.append(
            {"port": candidate_port, "result": outcome.result, "ms": outcome.ms}
        )
        if outcome.result == "open":
            break
    result["probes"] = probes

    if probes[-1]["result"] == "open":
        result["verdict"] = VERDICT_UP
        result["reached"] = REACHED_SERVICE
        result["reason"] = (
            f"TCP {probes[-1]['port']} answered on {target} in {probes[-1]['ms']} ms"
        )
    else:
        result["verdict"] = VERDICT_DEGRADED
        summary = ", ".join(f"{p['port']}={p['result']}" for p in probes)
        result["reason"] = (
            f"guest address {target} is reachable, but no probed service "
            f"answered ({summary})"
        )

    return result
