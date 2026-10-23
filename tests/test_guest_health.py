"""Tests for the M3 `guest_health` tool and its ladder.

Split like the M1 suite: the *contracts* (which rung failed, what is reported
for a host fault, which vmrun calls happen, which ports are probed) are tested
against fakes with no VMware process started, because those are the answers
that must be stable under any lab state.

The live tests at the bottom exercise the real instrument against whatever VM
is powered on right now. They skip when the lab is powered down, on purpose:
the suite must stay green for someone running it on a machine where nothing
is booted, and the down-path gets its own live gate for the same reason.

Run:
    .venv\\Scripts\\python.exe -m pytest tests/test_guest_health.py -v
"""

from __future__ import annotations

import asyncio
import ipaddress
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.server.mcpserver.context import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolRequestParams

import vm_mcp.health as health
import vm_mcp.vmrun as vmrun
from vm_mcp import roster, server
from vm_mcp.health import ProbeOutcome
from vm_mcp.vmrun import VmrunUnavailable, list_running_vmx

# --- fixtures ------------------------------------------------------------

DC01_UUID = "56 4d f4 8b bf be 94 a5-f8 b5 17 60 df 89 9e 33"
WAZUH_UUID = "56 4d e0 b5 86 57 4b 06-5c 82 f2 7e 01 37 b4 1d"

MAC0 = "00:0c:29:89:9e:33"  # the NAT NIC, startConnected FALSE on the live VM
MAC1 = "00:0c:29:89:9e:3d"  # the NIC that actually carries the guest traffic

FIELDS: dict[str, str] = {
    "displayname": "provider: GOAD-DC01",
    "guestos": "windows9srv-64",
    "numvcpus": "2",
    "memsize": "3000",
    "ethernet0.present": "TRUE",
    "ethernet0.connectiontype": "nat",
    "ethernet0.startconnected": "FALSE",
    "ethernet0.generatedaddress": MAC0,
    "ethernet1.present": "TRUE",
    "ethernet1.connectiontype": "custom",
    "ethernet1.generatedaddress": MAC1,
}

# .vmx fixture text carrying the same ethernet block, so the tool-level tests
# read the MACs out of a real file.
DC01_VMX = """\
.encoding = "UTF-8"
displayname = "provider: GOAD-DC01"
guestos = "windows9srv-64"
numvcpus = "2"
memsize = "3000"
ethernet0.present = "TRUE"
ethernet0.connectiontype = "nat"
ethernet0.startConnected = "FALSE"
ethernet0.generatedAddress = "00:0C:29:89:9E:33"
ethernet1.present = "TRUE"
ethernet1.connectionType = "custom"
ethernet1.generatedAddress = "00:0C:29:89:9E:3D"
uuid.bios = "56 4d f4 8b bf be 94 a5-f8 b5 17 60 df 89 9e 33"
"""

WAZUH_VMX = """\
.encoding = "UTF-8"
displayName = "wazuh-4.7.5"
guestos = "otherlinux-64"
numvcpus = "4"
memsize = "8192"
uuid.bios = "56 4d e0 b5 86 57 4b 06-5c 82 f2 7e 01 37 b4 1d"
"""

# `arp -a` output, byte-for-byte the shape observed on this host, including the
# localized header lines that render as mojibake on its cp866 console -- the
# parser must read the numeric columns only.
ARP_SAMPLE = "\n".join(
    [
        "",
        "  \xc8\xed\xf2\xe5\xf0\xf4\xe5\xe9\xea: 192.168.158.1 --- 0x6",
        "  192.168.158.254       00-50-56-eb-6e-f2     dynamic",
        "  192.168.158.255       ff-ff-ff-ff-ff-ff     broadcast",
        "",
        "  \xc8\xed\xf2\xe5\xf0\xf4\xe5\xe9\xea: 192.168.0.125 --- 0x10",
        "  192.168.0.1           28-ee-52-63-a2-17     dynamic",
        "  192.168.0.10          00-0c-29-89-9e-3d     dynamic",
        "  192.168.0.255         ff-ff-ff-ff-ff-ff     broadcast",
        "  224.0.0.2             01-00-5e-00-00-02     static",
        "",
        "  100.109.245.13                              invalid",
        "",
    ]
)


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A synthetic lab: registry + two .vmx files, wired into the modules."""
    vmx_dir = tmp_path / "vmx"
    vmx_dir.mkdir()
    dc01 = vmx_dir / "dc01.vmx"
    dc01.write_text(DC01_VMX, encoding="utf-8")
    wazuh = vmx_dir / "wazuh.vmx"
    wazuh.write_text(WAZUH_VMX, encoding="utf-8")

    registry_file = tmp_path / "inventory.vmls"
    registry_file.write_bytes(
        "\r\n".join(
            [
                '.encoding = "windows-1251"',
                f'vmlist1.config = "{dc01}"',
                'vmlist1.DisplayName = "provider: GOAD-DC01"',
                f'vmlist1.UUID = "{DC01_UUID}"',
                f'vmlist2.config = "{wazuh}"',
                'vmlist2.DisplayName = "wazuh-4.7.5"',
                f'vmlist2.UUID = "{WAZUH_UUID}"',
            ]
        ).encode("windows-1251")
    )
    monkeypatch.setattr(roster, "inventory_path", lambda: registry_file)

    return {"dc01": dc01, "wazuh": wazuh}


# The `vmrun list` answer every default-shape fake uses: the VM under test is
# powered on. The powered-off paths pass `running=[]` explicitly, which is the
# assertion that they really do exercise the off branch.
DEFAULT_RUNNING = ["C:\\v\\dc01.vmx"]


class Fakes:
    """The dependencies of `check_health`, rerouted with a call recorder.

    `running` defaults to the VM powered on, so each test states only what it
    is trying to pin; `probes` is the outcome queue the fake prober works
    through, defaulting to one open answer and then timeouts for any further
    attempt.
    """

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        running: list[str] | None = None,
        list_error: Exception | None = None,
        tools: str | None = "running",
        tools_error: Exception | None = None,
        guest_ip: str | None = None,
        guest_ip_error: Exception | None = None,
        neighbors: dict[str, str] | None = None,
        subnets: tuple[str, ...] = ("192.168.0.0/24",),
        probes: list[ProbeOutcome] | None = None,
    ) -> None:
        self.running = DEFAULT_RUNNING if running is None else running
        self.list_calls = 0
        self.tools_calls: list[str] = []
        self.guest_ip_calls: list[str] = []
        self.probe_calls: list[tuple[str, int]] = []
        self.outcomes = list(probes or [ProbeOutcome("open", 2)])

        async def fake_list(**_: Any) -> list[str]:
            self.list_calls += 1
            if list_error:
                raise list_error
            return list(self.running)

        async def fake_tools(vmx: str, **_: Any) -> str:
            self.tools_calls.append(vmx)
            if tools_error:
                raise tools_error
            return tools or ""

        async def fake_guest_ip(vmx: str, **_: Any) -> str | None:
            self.guest_ip_calls.append(vmx)
            if guest_ip_error:
                raise guest_ip_error
            return guest_ip

        async def fake_probe(
            ip: str, port: int, *, timeout: float = 2.0
        ) -> ProbeOutcome:
            self.probe_calls.append((ip, port))
            if self.outcomes:
                return self.outcomes.pop(0)
            return ProbeOutcome("timeout", 2000)

        monkeypatch.setattr(health, "list_running_vmx", fake_list)
        monkeypatch.setattr(health, "tools_state", fake_tools)
        monkeypatch.setattr(health, "get_guest_ip", fake_guest_ip)
        monkeypatch.setattr(health, "tcp_probe", fake_probe)
        monkeypatch.setattr(health, "neighbor_entries", lambda: dict(neighbors or {}))
        monkeypatch.setattr(
            health,
            "host_subnets",
            lambda: [ipaddress.ip_network(s) for s in subnets],
        )


def ladder(
    fakes: Fakes | None,
    fields: dict[str, str] | None = None,
    *,
    family: str = "windows",
    **kwargs: Any,
) -> dict[str, Any]:
    merged = dict(FIELDS)
    if fields:
        merged.update(fields)
    return asyncio.run(
        health.check_health("C:\\v\\dc01.vmx", merged, family=family, **kwargs)
    )


def call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    return asyncio.run(fn(*args, **kwargs))


# --- the ladder ----------------------------------------------------------


def test_powered_off_is_down_and_ladder_stops(monkeypatch) -> None:
    """A powered-off guest is `down`, and nothing further is paid for.

    checkToolsState on a powered-off VM spends seconds answering `installed`,
    which carries no information; the tools rung must not be reached.
    """
    fakes = Fakes(monkeypatch, running=[])

    result = ladder(fakes)

    assert result["verdict"] == "down"
    assert result["reached"] == "power"
    assert result["power_state"] == "stopped"
    assert result["reason"] == "not in vmrun's running list"
    assert "tools_state" not in result
    assert fakes.tools_calls == [], "tools rung skipped for a powered-off VM"
    assert fakes.probe_calls == []


def test_booting_guest_is_degraded_at_the_tools_rung(monkeypatch) -> None:
    """`installed` while powered on means up-but-not-answering: `degraded`.

    This is the case the tool exists to catch -- issue #12's "powered on but
    not answering" -- and the reason must name the rung that refused.
    """
    Fakes(monkeypatch, tools="installed")

    result = ladder(None)

    assert result["verdict"] == "degraded"
    assert result["reached"] == "tools"
    assert result["power_state"] == "running"
    assert "Tools" in result["reason"]
    assert "probes" not in result


def test_unexpected_tools_answer_is_reported_verbatim(monkeypatch) -> None:
    """An unexpected Tools value is shown, never normalized into a verdict."""
    fakes = Fakes(monkeypatch, tools="undetermined")

    result = ladder(fakes)

    assert result["verdict"] == "degraded"
    assert "'undetermined'" in result["reason"]
    assert result["tools_state"] == "undetermined"


def test_unreachable_tools_state_is_degraded_with_the_reason(monkeypatch) -> None:
    """vmrun answered the list but could not answer checkToolsState.

    We *know* the guest is on. `degraded` with the fault named is honest;
    `unknown` would throw away a rung that was actually climbed.
    """
    fakes = Fakes(monkeypatch, tools_error=VmrunUnavailable("timed out after 20s"))

    result = ladder(fakes)

    assert result["verdict"] == "degraded"
    assert result["reached"] == "tools"
    assert "timed out after 20s" in result["reason"]
    assert "probes" not in result


def test_unreachable_vmrun_is_unknown(monkeypatch) -> None:
    """A host fault is `unknown`, never `down`.

    Reporting the lab's domain controllers as powered off during a host fault
    is the confident wrong answer this tool must never produce.
    """
    fakes = Fakes(monkeypatch, list_error=VmrunUnavailable("vmrun list failed"))

    result = ladder(fakes)

    assert result["verdict"] == "unknown"
    assert result["reached"] is None
    assert result["power_state"] == "unknown"
    assert "vmrun list failed" in result["reason"]


def test_no_reachable_address_is_degraded_at_the_tools_rung(monkeypatch) -> None:
    """Tools running, but no route to the guest: `degraded`, with detail."""
    fakes = Fakes(monkeypatch, guest_ip=None, neighbors={})

    result = ladder(fakes)

    assert result["verdict"] == "degraded"
    assert result["reached"] == "tools"
    assert "address" in result["reason"]
    assert "probes" not in result


def test_unroutable_candidate_is_rejected_and_shown_not_probed(monkeypatch) -> None:
    """The B2 case: getGuestIPAddress names the unroutable static address.

    It must appear under `rejected_addresses` -- visible, not silently
    dropped -- and must not cost a probe, because a connect to an unroutable
    address is a guaranteed timeout that says nothing.
    """
    fakes = Fakes(monkeypatch, guest_ip="192.168.230.3", neighbors={})

    result = ladder(fakes)

    assert result["verdict"] == "degraded"
    assert result["rejected_addresses"] == ["192.168.230.3"]
    assert "192.168.230.3" in result["reason"]
    assert fakes.probe_calls == []


def test_neighbor_cache_finds_the_bridged_address_by_mac(monkeypatch) -> None:
    """The credential-free fallback that unmakes blocker B2.

    vmrun reports nothing host-reachable; the .vmx declares a NIC MAC and the
    neighbor cache has that MAC at the DHCP-per-boot bridged address. The
    discovered address must be probed and the source must say where it came
    from.
    """
    fakes = Fakes(monkeypatch, guest_ip=None, neighbors={MAC1: "192.168.0.10"})

    result = ladder(fakes)

    assert result["verdict"] == "up"
    assert result["address"] == "192.168.0.10"
    assert result["address_source"] == "neighbor-cache"
    assert fakes.probe_calls == [("192.168.0.10", 3389)]


def test_get_guest_ip_validated_then_probed(monkeypatch) -> None:
    """When vmrun's answer checks out it becomes the probe target directly."""
    fakes = Fakes(monkeypatch, guest_ip="192.168.0.10")

    result = ladder(fakes)

    assert result["verdict"] == "up"
    assert result["address"] == "192.168.0.10"
    assert result["address_source"] == "get-guest-ip"
    assert fakes.probe_calls == [("192.168.0.10", 3389)]


def test_rdp_refused_smb_open_is_up_on_the_second_port(monkeypatch) -> None:
    """A closed first port does not end the ladder.

    3389 refusing while 445 answers is still a live server; the probe order
    exists precisely so the second port gets its turn, and both attempts are
    reported.
    """
    fakes = Fakes(
        monkeypatch,
        guest_ip="192.168.0.10",
        probes=[ProbeOutcome("refused", 1), ProbeOutcome("open", 3)],
    )

    result = ladder(fakes)

    assert result["verdict"] == "up"
    assert result["reached"] == "service"
    assert [p["result"] for p in result["probes"]] == ["refused", "open"]
    assert result["probes"][-1]["port"] == 445
    assert "445" in result["reason"]


def test_every_probed_port_refused_is_degraded_with_both_reported(
    monkeypatch,
) -> None:
    """Both Windows ports answering nothing: degraded, with the full picture.

    The guest is demonstrably reachable (two RSTs came back), so this is not
    `down` and not `unknown` -- it is a live machine nobody can work with.
    """
    fakes = Fakes(
        monkeypatch,
        guest_ip="192.168.0.10",
        probes=[ProbeOutcome("refused", 1), ProbeOutcome("refused", 2)],
    )

    result = ladder(fakes)

    assert result["verdict"] == "degraded"
    assert result["reached"] == "address"
    assert [p["result"] for p in result["probes"]] == ["refused", "refused"]
    assert "3389=refused" in result["reason"]


def test_probe_timeout_is_degraded(monkeypatch) -> None:
    """A silent port is not an error and not `unknown`: a timed-out rung.

    A timeout does not end the ladder -- only an `open` does -- so both
    Windows ports are tried, and each carries its own row in `probes`.
    """
    fakes = Fakes(
        monkeypatch,
        guest_ip="192.168.0.10",
        probes=[ProbeOutcome("timeout", 2000)],
    )

    result = ladder(fakes)

    assert result["verdict"] == "degraded"
    assert result["reached"] == "address"
    assert [p["port"] for p in result["probes"]] == [3389, 445]
    assert all(p["result"] == "timeout" for p in result["probes"])
    assert "3389=timeout" in result["reason"]


def test_probe_error_falls_through_to_the_next_port(monkeypatch) -> None:
    """A non-answer on one port does not end the ladder either."""
    fakes = Fakes(
        monkeypatch,
        guest_ip="192.168.0.10",
        probes=[ProbeOutcome("error", 500, "unroutable"), ProbeOutcome("open", 2)],
    )

    result = ladder(fakes)

    assert result["verdict"] == "up"
    assert [p["port"] for p in result["probes"]] == [3389, 445]


def test_port_override_is_used_alone(monkeypatch) -> None:
    """An explicit port replaces the family defaults, it does not add to them."""
    fakes = Fakes(monkeypatch, guest_ip="192.168.0.10", probes=[ProbeOutcome("open", 1)])

    result = ladder(fakes, port=5985)

    assert result["verdict"] == "up"
    assert result["probes"][0]["port"] == 5985
    assert fakes.probe_calls == [("192.168.0.10", 5985)]


def test_family_without_default_ports_skips_discovery(monkeypatch) -> None:
    """An unclassified guest gets no made-up probe and no address discovery.

    There is no honest port to knock on for `other`, and discovery would be
    paid for nothing; the result says exactly what is missing instead.
    """
    fakes = Fakes(monkeypatch)

    result = ladder(fakes, family="other")

    assert result["verdict"] == "degraded"
    assert result["reached"] == "tools"
    assert "port" in result["reason"]
    assert fakes.guest_ip_calls == [], "discovery was paid for nothing"
    assert "probes" not in result


def test_linux_family_probes_ssh(monkeypatch) -> None:
    """Default ports come from the family: a Linux guest is probed on 22."""
    fakes = Fakes(
        monkeypatch,
        guest_ip="192.168.0.11",
        probes=[ProbeOutcome("open", 4)],
    )
    fields = {k: v for k, v in FIELDS.items() if not k.startswith("ethernet")}
    fields["guestos"] = "otherlinux-64"

    result = ladder(fakes, fields, family="linux")

    assert result["verdict"] == "up"
    assert result["probes"] == [{"port": 22, "result": "open", "ms": 4}]


# --- get_guest_ip --------------------------------------------------------


def test_get_guest_ip_returns_the_answer(monkeypatch) -> None:
    calls: list[list[str]] = []

    async def fake_run(args: list[str], **_: Any) -> vmrun.VmrunResult:
        calls.append(args)
        return vmrun.VmrunResult(ok=True, stdout="192.168.0.10\n", exit_code=0)

    monkeypatch.setattr(vmrun, "run_vmrun", fake_run)

    assert asyncio.run(vmrun.get_guest_ip("C:\\v\\dc01.vmx")) == "192.168.0.10"
    assert calls == [["getGuestIPAddress", "C:\\v\\dc01.vmx"]]


def test_get_guest_ip_returns_none_when_vmrun_declines(monkeypatch) -> None:
    """A powered-off guest exits non-zero: the guest's problem, not a fault."""

    async def fake_run(args: list[str], **_: Any) -> vmrun.VmrunResult:
        return vmrun.VmrunResult(
            ok=False, stdout="Error: The VM is not powered on", exit_code=1
        )

    monkeypatch.setattr(vmrun, "run_vmrun", fake_run)

    assert asyncio.run(vmrun.get_guest_ip("C:\\v\\dc01.vmx")) is None


def test_get_guest_ip_returns_none_on_empty_success(monkeypatch) -> None:
    """Exit 0 with nothing to show is no address, not an empty-string IP."""

    async def fake_run(args: list[str], **_: Any) -> vmrun.VmrunResult:
        return vmrun.VmrunResult(ok=True, stdout="", exit_code=0)

    monkeypatch.setattr(vmrun, "run_vmrun", fake_run)

    assert asyncio.run(vmrun.get_guest_ip("C:\\v\\dc01.vmx")) is None


def test_get_guest_ip_lets_vmrun_faults_propagate(monkeypatch) -> None:
    """A host fault stays distinguishable from "no address" at the boundary."""

    async def fake_run(args: list[str], **_: Any) -> vmrun.VmrunResult:
        raise VmrunUnavailable("vmrun timed out after 20.0s")

    monkeypatch.setattr(vmrun, "run_vmrun", fake_run)

    with pytest.raises(VmrunUnavailable):
        asyncio.run(vmrun.get_guest_ip("C:\\v\\dc01.vmx"))


# --- the pieces ----------------------------------------------------------


def test_neighbor_entries_parses_numeric_columns_only(monkeypatch) -> None:
    """Localized headers and an entry without a MAC must not break the parse."""

    def fake_run(args: list[str], **_: Any) -> SimpleNamespace:
        assert args == ["arp", "-a"]
        return SimpleNamespace(stdout=ARP_SAMPLE.encode("utf-8"))

    monkeypatch.setattr(subprocess, "run", fake_run)

    entries = health.neighbor_entries()

    assert entries[MAC1] == "192.168.0.10"
    assert entries["28:ee:52:63:a2:17"] == "192.168.0.1"
    # The broadcast row parses too, harmless -- no VM owns that MAC. It appears
    # on both interfaces; the first mention wins, and the row is not a VM.
    assert entries["ff:ff:ff:ff:ff:ff"] == "192.168.158.255"
    # The MAC-less line was dropped rather than guessed into the table.
    assert "100.109.245.13" not in entries.values()


def test_vmx_macs_reads_both_address_spellings() -> None:
    """`generatedAddress` and `address` are both read; garbage is dropped.

    An adapter that is not `present` at all is excluded, while one that is
    present but not connected at power-on (`startConnected = FALSE`, like the
    live VM's NAT NIC) is included: it is a declared adapter whose MAC simply
    will not match any cache entry, which the discovery treats as the
    observation that the adapter is not live.
    """
    fields = {
        "ethernet0.present": "TRUE",
        "ethernet0.generatedaddress": "00:0C:29:89:9E:33",
        "ethernet1.present": "TRUE",
        "ethernet1.address": "02-AB-CD-EF-01-02",
        "ethernet2.present": "TRUE",  # no MAC at all
        "ethernet3.present": "FALSE",
        "ethernet3.generatedaddress": MAC1,  # not present -> excluded
        "ethernet4.present": "TRUE",
        "ethernet4.generatedaddress": "not-a-mac",
    }

    assert health.vmx_macs(fields) == [MAC0, "02:ab:cd:ef:01:02"]


def test_reachability_check_rejects_link_local_and_loopback(monkeypatch) -> None:
    """The guard is not redundancy: even if a link-local subnet somehow shows
    up in the host's interface list, its addresses are not probe targets."""

    def fake_subnets() -> list[ipaddress.IPv4Network]:
        return [
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("192.168.0.0/24"),
        ]

    monkeypatch.setattr(health, "host_subnets", fake_subnets)
    subnets = health.host_subnets()

    assert health._on_host_subnet("169.254.90.245", subnets) is False
    assert health._on_host_subnet("127.0.0.1", subnets) is False
    assert health._on_host_subnet("192.168.0.10", subnets) is True
    assert health._on_host_subnet("nonsense", subnets) is False


# --- the tool -------------------------------------------------------------


def test_guest_health_reports_up_end_to_end(lab, monkeypatch) -> None:
    """Registry -> .vmx -> family -> ladder -> verdict, through the tool."""
    fakes = Fakes(monkeypatch, running=[str(lab["dc01"])], guest_ip="192.168.0.10")

    result = call(server.guest_health, name="provider: GOAD-DC01")

    assert result["verdict"] == "up"
    assert result["reached"] == "service"
    assert result["power_state"] == "running"
    assert result["tools_state"] == "running"
    assert result["address"] == "192.168.0.10"
    assert result["address_source"] == "get-guest-ip"
    assert result["probes"] == [{"port": 3389, "result": "open", "ms": 2}]
    assert result["vmx_exists"] is True
    assert fakes.probe_calls == [("192.168.0.10", 3389)]


def test_guest_health_selects_the_linux_port_from_the_vmx(lab, monkeypatch) -> None:
    """The wazuh manager is `otherlinux-64`; the tool probes 22, not 3389."""
    fakes = Fakes(monkeypatch, running=[str(lab["wazuh"])], guest_ip="192.168.0.11")

    result = call(server.guest_health, name="wazuh-4.7.5")

    assert result["verdict"] == "up"
    assert fakes.probe_calls == [("192.168.0.11", 22)]


def test_guest_health_schema_takes_two_identifiers_and_a_port() -> None:
    async def go() -> dict[str, Any]:
        tools = {t.name: t for t in await server.mcp.list_tools()}
        return tools["guest_health"].input_schema

    schema = asyncio.run(go())

    assert set(schema["properties"]) == {"uuid", "name", "port"}
    assert not schema.get("required"), (
        "the tool reports an error when neither identifier is given, rather "
        "than making the model manufacture one"
    )
    for prop in ("uuid", "name"):
        kinds = {t.get("type") for t in schema["properties"][prop]["anyOf"]}
        assert kinds == {"string", "null"}, f"{prop} must accept null"
    port_kinds = {t.get("type") for t in schema["properties"]["port"]["anyOf"]}
    assert port_kinds == {"integer", "null"}


def test_unresolved_identifier_is_an_error_before_any_vmrun_call(
    lab, monkeypatch
) -> None:
    """The property every tool in this server inherits from the roster:
    an identifier that does not resolve starts no VMware process."""
    fakes = Fakes(monkeypatch)

    with pytest.raises(ToolError, match="definitely-not-a-vm"):
        call(server.guest_health, name="definitely-not-a-vm")

    assert fakes.list_calls == 0


def test_guest_health_rejects_an_out_of_range_port(lab, monkeypatch) -> None:
    Fakes(monkeypatch)

    with pytest.raises(ToolError, match="between 1 and 65535"):
        call(server.guest_health, name="provider: GOAD-DC01", port=70000)


def test_guest_health_rejects_a_zero_port(lab, monkeypatch) -> None:
    Fakes(monkeypatch)

    with pytest.raises(ToolError, match="between 1 and 65535"):
        call(server.guest_health, name="provider: GOAD-DC01", port=0)


def test_port_validation_happens_before_any_vmrun_call(lab, monkeypatch) -> None:
    """A bad port must not send the ladder climbing half way up."""
    fakes = Fakes(monkeypatch)

    with pytest.raises(ToolError):
        call(server.guest_health, name="provider: GOAD-DC01", port=70000)

    assert fakes.list_calls == 0


def test_stale_registry_entry_reports_why_it_is_down(lab, monkeypatch) -> None:
    """A missing .vmx cannot run: `down`, and the reason says why it cannot."""
    fakes = Fakes(monkeypatch, running=[])
    lab["dc01"].unlink()

    result = call(server.guest_health, name="provider: GOAD-DC01")

    assert result["vmx_exists"] is False
    assert result["verdict"] == "down"
    assert ".vmx is missing" in result["reason"]
    assert fakes.list_calls == 1


def test_guest_health_is_error_reaches_the_protocol_layer(lab, monkeypatch) -> None:
    """End to end, as the model sees it, like the M1 contract test."""
    Fakes(monkeypatch)

    async def go() -> Any:
        ctx = Context(mcp_server=server.mcp, subscriptions=server.mcp._subscriptions)
        return await server.mcp._handle_call_tool(
            ctx,
            CallToolRequestParams(name="guest_health", arguments={"name": "nope"}),
        )

    result = asyncio.run(go())

    assert result.is_error is True
    assert "nope" in result.content[0].text


# --- live: real vmrun, real probe; skipped when the lab is powered down ---


def _live_running() -> list[str]:
    try:
        return asyncio.run(list_running_vmx())
    except Exception:
        return []


_RUNNING_AT_COLLECTION = _live_running()


def _norm_list(paths: list[str]) -> set[str]:
    return {p.replace("/", "\\").lower() for p in paths}


def test_live_running_vm_reports_a_verdict_with_evidence() -> None:
    """Every powered-on registered VM comes back with a verdict and its rung.

    `up` is the expected answer for a settled guest on this lab; a VM caught
    mid-boot is `degraded` and must still name the rung, never fail the call.
    """
    running_norm = _norm_list(_RUNNING_AT_COLLECTION)
    candidates = [
        vm
        for vm in roster.registry().vms
        if vm.vmx.replace("/", "\\").lower() in running_norm
    ]
    if not candidates:
        pytest.skip("no registered VM is powered on right now")

    for vm in candidates:
        result = call(server.guest_health, uuid=vm.uuid)

        assert result["power_state"] == "running", result
        assert result["verdict"] in {"up", "degraded"}, result
        assert result["reached"] in {"power", "tools", "address", "service"}, result
        assert result["reason"], result
        if result["verdict"] == "up":
            assert result["address"], result
            assert result["probes"][-1]["result"] == "open", result
            assert result["probes"][-1]["ms"] >= 1, result


def test_live_powered_off_vm_is_down() -> None:
    """The cheap half of the ladder against real VMware: off must be `down`."""
    running_norm = _norm_list(_RUNNING_AT_COLLECTION)
    candidates = [
        vm
        for vm in roster.registry().vms
        if vm.vmx.replace("/", "\\").lower() not in running_norm
    ]
    if not candidates:
        pytest.skip("every registered VM is powered on right now")

    result = call(server.guest_health, uuid=candidates[0].uuid)

    assert result["verdict"] == "down"
    assert result["reached"] == "power"
    assert result["power_state"] == "stopped"
