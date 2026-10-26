"""Tests for the M1 tool surface: `list_vms` and `vm_status`.

Every test here runs against a fake vmrun and a synthetic registry. No VMware
process is started and no VM is touched — the point of these tests is the tool
*contracts* (which fields are present, what is reported when a host is
unreachable, which vmrun calls are and are not made), and those are exactly the
things that are expensive to check against real hardware.

The behaviours pinned here are the ones that were verified against real
VMware Workstation during M1 and are easy to regress:

* `vmrun list` prints `Total running VMs: N` then N paths, CRLF-terminated,
  and only for VMs that are powered on.
* A failure exits -1 and prints `Error: ...` on **stdout**, not stderr. Code
  that reads only stderr would treat that as data.
* `checkToolsState` costs 0.65-3.5s and answers `installed` for a powered-off
  VM, which means nothing. It is only worth calling for a running guest.
* `.vmx` keys are inconsistently cased in the wild (`displayname` vs
  `displayName`).

Run:
    .venv\\Scripts\\python.exe -m pytest tests/test_vm_mcp.py -v
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable

import pytest
from mcp.server.mcpserver.context import Context

from vm_mcp import roster, server
from vm_mcp.vmrun import VmrunResult, parse_list_output

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

# Real .vmx content, trimmed. `displayname` lowercase here and `displayName` on
# the other fixture, because the live lab has both.
DC01_VMX = """\
.encoding = "UTF-8"
config.version = "8"
displayname = "provider: GOAD-DC01"
guestos = "windows9srv-64"
memcfg = "3000"
numvcpus = "2"
memsize = "3000"
scsi0.present = "TRUE"
uuid.bios = "56 4d f4 8b bf be 94 a5-f8 b5 17 60 df 89 9e 33"
"""

WAZUH_VMX = """\
.encoding = "UTF-8"
config.version = "8"
displayName = "wazuh-4.7.5"
guestos = "otherlinux-64"
numvcpus = "4"
memsize = "8192"
uuid.bios = "56 4d e0 b5 86 57 4b 06-5c 82 f2 7e 01 37 b4 1d"
"""

class FakeVmrun:
    """Records calls and returns canned results. Refuses to be forgotten."""

    def __init__(
        self,
        *,
        list_result: VmrunResult | None = None,
        list_error: Exception | None = None,
        tools_result: VmrunResult | None = None,
    ) -> None:
        self.calls: list[list[str]] = []
        self.list_result = list_result or VmrunResult(
            ok=True, stdout="Total running VMs: 0", exit_code=0
        )
        self.list_error = list_error
        self.tools_result = tools_result or VmrunResult(
            ok=True, stdout="running", exit_code=0
        )

    async def list_running_vmx(self, **_: Any) -> list[str]:
        self.calls.append(["list"])
        if self.list_error:
            raise self.list_error
        return parse_list_output(self.list_result.stdout)

    async def tools_state(self, vmx: str, **_: Any) -> str:
        self.calls.append(["checkToolsState", vmx])
        if self.tools_result is not False:  # type: ignore[comparison-overlap]
            return self.tools_result.stdout.strip().lower()
        raise AssertionError("tools_state must not be called for a stopped VM")


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A synthetic lab: registry + two .vmx files, wired into the module.

    The registry is rewritten to point at the real .vmx files created under
    tmp_path, so `vmx_exists` and the .vmx read are exercised against actual
    bytes. `running_vmx` carries the rewritten path, because a canned vmrun
    listing has to name the same path the registry does or the power state will
    not match.
    """
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

    return {
        "registry": registry_file,
        "dc01": dc01,
        "wazuh": wazuh,
        "running_vmx": str(dc01),
    }


def three_running(running_vmx: str) -> str:
    """`vmrun list` output for three running VMs, one of them `running_vmx`.

    Byte-for-byte the shape observed on the M0 host: a `Total running VMs: N`
    header, then N CRLF-terminated paths, no blank line.
    """
    return (
        "Total running VMs: 3\r\n"
        "D:\\vms\\goad\\PROVISIONING\\ubuntu-22.04-amd64.vmx\r\n"
        "D:\\vms\\Ubuntu_20.04.4_VM\\Ubuntu_20.04.4_VM_LinuxVMImages.COM.vmx\r\n"
        f"{running_vmx}\r\n"
    )


@pytest.fixture
def vmrun(monkeypatch: pytest.MonkeyPatch) -> Callable[..., FakeVmrun]:
    """Factory that installs a FakeVmrun in place of the real one."""

    def install(**kwargs: Any) -> FakeVmrun:
        fake = FakeVmrun(**kwargs)
        monkeypatch.setattr(server, "list_running_vmx", fake.list_running_vmx)
        monkeypatch.setattr(server, "tools_state", fake.tools_state)
        return fake

    return install


def call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return asyncio.run(fn(*args, **kwargs))


# --- vmrun output parsing ------------------------------------------------


def test_parses_three_running_vms() -> None:
    """Verified against a real 3-VM run. The header count is not trusted; the
    returned list is built from the paths actually present."""
    stdout = three_running(RUNNING_VMX)

    assert parse_list_output(stdout) == [
        r"D:\vms\goad\PROVISIONING\ubuntu-22.04-amd64.vmx",
        r"D:\vms\Ubuntu_20.04.4_VM\Ubuntu_20.04.4_VM_LinuxVMImages.COM.vmx",
        RUNNING_VMX,
    ]


def test_zero_running_yields_empty_list() -> None:
    assert parse_list_output("Total running VMs: 0") == []


def test_error_line_is_not_mistaken_for_a_path() -> None:
    """vmrun prints `Error: Cannot open VM:` on stdout with exit -1. Anything
    that is not a .vmx path must be dropped, not passed off as a VM."""
    stdout = "Total running VMs: 1\nError: Cannot open VM: C:\\nope.vmx\n"
    assert parse_list_output(stdout) == []


# --- list_vms ------------------------------------------------------------


def test_list_vms_reports_every_registered_vm(lab, vmrun) -> None:
    vmrun()
    result = call(server.list_vms)

    assert result["counts"] == {"total": 2, "running": 0}
    assert {v["name"] for v in result["vms"]} == {
        "provider: GOAD-DC01",
        "wazuh-4.7.5",
    }


def test_list_vms_carries_no_configuration_fields(lab, vmrun) -> None:
    """Identity and power state only.

    CPU and RAM belong to `vm_status`. Putting them here means a caller asking
    "what is on this box" reads every .vmx to answer a question about the lab.
    """
    vmrun()
    entry = call(server.list_vms)["vms"][0]

    assert set(entry) == {"name", "uuid", "power_state"}


def test_list_vms_omits_the_vmx_path(lab, vmrun) -> None:
    """No path in the list.

    A caller cannot act on a path -- vm_status resolves against the registry, not
    a file -- and the Vagrant paths run about 190 characters each. Across eight
    VMs that is most of the payload for information nothing can use. vm_status
    still returns it, where it is worth the characters.
    """
    vmrun()
    result = call(server.list_vms)

    assert all("vmx" not in vm for vm in result["vms"])
    assert "vmx" in call(server.vm_status, name="provider: GOAD-DC01")


def test_list_vms_and_vm_status_see_the_same_registry(lab, vmrun) -> None:
    """The two tools must never disagree about which VMs exist.

    list_vms used to re-read the registry while vm_status used a cached
    snapshot, so a VM registered after startup appeared in the list and was then
    reported as unknown by name. Same server, same instant, two different
    answers.
    """
    vmrun()
    listed = {vm["uuid"] for vm in call(server.list_vms)["vms"]}

    for name in ("provider: GOAD-DC01", "wazuh-4.7.5"):
        assert call(server.vm_status, name=name)["uuid"] in listed


def test_vm_registered_after_startup_is_visible_to_both_tools(
    lab, vmrun, tmp_path
) -> None:
    """A VM added to the registry while the server is already running resolves
    on the next call, with no refresh step in between.

    This is the bug that made the tools order-dependent: `list_vms` re-read the
    registry and `vm_status` read a cached snapshot, so a newly registered VM
    was listed and then reported as unknown by name.
    """
    vmrun()
    lab["registry"].write_bytes(
        lab["registry"].read_bytes()
        + f'\r\nvmlist3.config = "{RUNNING_VMX}"\r\n'
        'vmlist3.DisplayName = "LateVM"\r\n'
        'vmlist3.UUID = "ff 00 00 00 00 00 00 00-00 00 00 00 00 00 00 09"\r\n'.encode(
            "windows-1251"
        )
    )

    listed = {vm["name"] for vm in call(server.list_vms)["vms"]}
    assert "LateVM" in listed
    assert call(server.vm_status, name="LateVM")["name"] == "LateVM"


def test_list_vms_marks_only_listed_vms_running(lab, vmrun) -> None:
    fake = vmrun(
        list_result=VmrunResult(True, three_running(lab["running_vmx"]), 0)
    )

    result = call(server.list_vms)
    states = {v["name"]: v["power_state"] for v in result["vms"]}

    assert states["provider: GOAD-DC01"] == "running"
    assert states["wazuh-4.7.5"] == "stopped"
    assert result["counts"]["running"] == 1
    assert fake.calls == [["list"]]


def test_unreachable_vmrun_is_reported_as_unknown_not_stopped(
    lab, vmrun
) -> None:
    """The distinction that matters.

    If vmrun cannot be reached, "unknown" is the only honest answer. Reporting
    `stopped` would tell the model every domain controller in the lab is powered
    off, during a host fault, with total confidence.
    """
    from vm_mcp.vmrun import VmrunUnavailable

    vmrun(list_error=VmrunUnavailable("vmrun timed out after 15.0s"))

    result = call(server.list_vms)

    assert result["observed_via"] == "unavailable"
    assert result["vmrun_error"]
    assert {v["power_state"] for v in result["vms"]} == {"unknown"}
    assert result["counts"]["running"] == 0


def test_list_vms_uses_one_vmrun_call(lab, vmrun) -> None:
    fake = vmrun()
    call(server.list_vms)
    assert fake.calls == [["list"]]


def test_unreadable_registry_is_reported_as_an_error(lab, vmrun, monkeypatch) -> None:
    """An unreadable registry must surface as an error, and must not spend a
    vmrun call with nothing to look up."""
    fake = vmrun()
    monkeypatch.setattr(
        roster, "registry", lambda *a, **k: roster.RosterSnapshot((), "registry gone")
    )

    result = call(server.list_vms)

    assert result["vms"] == []
    assert result["registry_error"] == "registry gone"
    assert result["observed_via"] == "unavailable"
    assert fake.calls == [], "no point calling vmrun with nothing to look up"


# --- vm_status -----------------------------------------------------------


def test_vm_status_reads_cpu_and_memory_from_the_vmx(lab, vmrun) -> None:
    vmrun()

    result = call(server.vm_status, uuid=DC01_UUID)

    assert result["vcpu"] == 2
    assert result["mem_mb"] == 3000
    assert result["guest_os"] == "windows9srv-64"


@pytest.mark.parametrize(
    ("guestos", "expected"),
    [
        pytest.param("windows9srv-64", "windows", id="server-2019"),
        pytest.param("windows9srv", "windows", id="server-32-bit"),
        pytest.param("win9x", "windows", id="win9x"),
        pytest.param("ubuntu-64", "linux", id="ubuntu"),
        pytest.param("rhel8-64", "linux", id="rhel"),
        pytest.param("otherlinux64", "linux", id="otherlinux-is-linux"),
        pytest.param("other", "other", id="genuinely-unclassified"),
        pytest.param("darwin-64", "macos", id="darwin-contains-win"),
        pytest.param("solaris-64", "solaris", id="solaris"),
        pytest.param("mystery-os", "unknown", id="unrecognised"),
    ],
)
def test_os_family_decodes_the_vendor_vocabulary(guestos: str, expected: str) -> None:
    """`guestos` values are VMware identifiers, not OS names.

    An agent asked "is this VM Windows?" would otherwise need to know that
    `windows9srv-64` means Server 2019 -- and a wrong guess there is worse than
    an honest `unknown`.

    Two cases carry the weight. `darwin-64` contains the substring "win", so
    matching by substring would report a macOS guest as Windows; hence prefixes.
    And `otherlinux-64` is mapped to `linux` despite meaning "Linux, distro
    unclassified" -- reporting it as `other` would make an agent enumerating
    Linux hosts skip the wazuh manager, which is Linux. The unclassified-distro
    detail is still in `guest_os`. `unknown` stays reserved for a field we could
    not read or interpret.
    """
    assert server.os_family(guestos) == expected


def test_otherlinux_guests_are_still_linux_in_a_live_status(lab, vmrun) -> None:
    """The host's wazuh manager is `otherlinux-64`. The regression this pins is
    an agent asking "which Linux hosts exist?" and getting 2 of 3."""
    vmrun()

    result = call(server.vm_status, uuid=WAZUH_UUID)

    assert result["guest_os"] == "otherlinux-64"
    assert result["os_family"] == "linux"


def test_vm_status_reports_os_family_beside_the_raw_value(lab, vmrun) -> None:
    """Both, because the raw value is the ground truth and the family is the
    convenience."""
    vmrun()

    result = call(server.vm_status, uuid=DC01_UUID)

    assert result["guest_os"] == "windows9srv-64"
    assert result["os_family"] == "windows"


def test_vm_status_does_not_repeat_the_display_name(lab, vmrun) -> None:
    """`name` already carries it.

    The registry display name and the `.vmx` `displayname` are identical on
    every VM checked, so the second copy is pure payload. Kept only if VMware
    ever makes them diverge, which it has not.
    """
    vmrun()

    result = call(server.vm_status, uuid=DC01_UUID)

    assert result["name"] == "provider: GOAD-DC01"
    assert "display_name" not in result


def test_vmx_keys_are_matched_case_insensitively(lab, vmrun, monkeypatch) -> None:
    """Live files use `displayname` and `displayName` interchangeably, and the
    lab has both spellings. A case-sensitive read returns nothing for half of
    it.

    Exercised through `guestos`, which is present in both files, rather than
    through `displayname`, which `vm_status` no longer returns.
    """
    vmrun()
    monkeypatch.setattr(server, "os_family", lambda _: "SENTINEL")

    assert call(server.vm_status, uuid=DC01_UUID)["os_family"] == "SENTINEL"
    assert call(server.vm_status, uuid=WAZUH_UUID)["os_family"] == "SENTINEL"


def test_vm_status_falls_back_to_name(lab, vmrun) -> None:
    vmrun()
    assert call(server.vm_status, name="wazuh-4.7.5")["uuid"] == WAZUH_UUID


def test_vm_status_accepts_a_dashed_uuid(lab, vmrun) -> None:
    vmrun()
    dashed = DC01_UUID.replace(" ", "").replace("-", "-")
    assert call(server.vm_status, uuid=dashed)["name"] == "provider: GOAD-DC01"


def test_unknown_identifier_starts_no_process(lab, vmrun) -> None:
    """The security-relevant test for this milestone.

    An identifier that does not resolve must not fall through to a vmrun call
    on anything. This is the property every future mutating tool inherits.
    """
    from mcp.server.mcpserver.exceptions import ToolError

    fake = vmrun()

    with pytest.raises(ToolError):
        call(server.vm_status, uuid="de ad be ef 00 00 00 00-00 00 00 00 00 00 00 ff")

    assert fake.calls == []


def test_ambiguous_name_is_an_error_listing_candidates(lab, vmrun, tmp_path) -> None:
    """Two VMs sharing a display name must produce an error the model can act
    on, so the message names the candidates rather than picking one."""
    from mcp.server.mcpserver.exceptions import ToolError

    registry_file = tmp_path / "inventory.vmls"
    registry_file.write_bytes(
        REGISTRY.replace(b"wazuh-4.7.5", b"provider: GOAD-DC01")
        .replace(str(lab["wazuh"]).encode(), b"C:\\VMs\\other.vmx")
    )
    vmrun()

    with pytest.raises(ToolError) as excinfo:
        call(server.vm_status, name="provider: GOAD-DC01")

    message = str(excinfo.value)
    assert "matches 2 VMs" in message, f"ambiguity must be stated: {message}"
    assert "uuid" in message.lower(), "the message must say how to disambiguate"


def test_contradictory_identifiers_explain_the_conflict(lab, vmrun) -> None:
    """Both identifiers supplied and disagreeing must say so, not resolve one.

    Also the regression guard for the shadowed `RosterError`: `IdentifierMismatch`
    stopped being catchable as `roster.RosterError`, so this used to escape the
    handler and reach the caller as a generic framework error with the
    explanation lost.
    """
    from mcp.server.mcpserver.exceptions import ToolError

    fake = vmrun()

    with pytest.raises(ToolError) as excinfo:
        call(server.vm_status, uuid=DC01_UUID, name="wazuh-4.7.5")

    message = str(excinfo.value)
    assert "provider: GOAD-DC01" in message
    assert "wazuh-4.7.5" in message
    assert fake.calls == [], "no VMware call may happen on an unresolved identifier"


def test_unresolvable_call_comes_back_as_is_error(lab, vmrun) -> None:
    """End to end at the protocol layer, not just the function body.

    `MCPServer.call_tool` raises; `_handle_call_tool` is what converts a
    deliberate failure into `is_error=True` with the message in the content.
    That is the contract the model sees, so it is the one worth asserting.
    Returning an error-shaped dict with `is_error=False` would have been a
    confident-looking wrong answer.
    """
    from mcp.types import CallToolRequestParams

    vmrun()

    async def go() -> Any:
        ctx = Context(mcp_server=server.mcp, subscriptions=server.mcp._subscriptions)
        return await server.mcp._handle_call_tool(
            ctx, CallToolRequestParams(name="vm_status", arguments={"name": "nope"})
        )

    result = asyncio.run(go())

    assert result.is_error is True
    assert "nope" in result.content[0].text


def test_unreachable_vmrun_also_comes_back_as_a_value_not_an_error(
    lab, vmrun
) -> None:
    """A host fault is a degraded answer, not a tool failure.

    `list_vms` still returns the registered VMs it knows about, marked
    `unknown`. That is more useful than an error, and more importantly it is not
    a false claim: the registry read genuinely succeeded.
    """
    from mcp.server.mcpserver.exceptions import ToolError

    from vm_mcp.vmrun import VmrunUnavailable

    vmrun(list_error=VmrunUnavailable("vmrun timed out after 15.0s"))

    result = call(server.list_vms)

    assert "error" not in result
    assert result["observed_via"] == "unavailable"
    assert {v["power_state"] for v in result["vms"]} == {"unknown"}


def test_tool_error_message_reaches_the_content(lab, vmrun) -> None:
    """A deliberate failure keeps its own text after the SDK's prefix.

    `ToolError` is documented as: "the call returns is_error=True with your
    message in content". If the SDK ever stops preserving it, the model would be
    left with only `Error executing tool vm_status` and no way to correct itself.
    """
    from mcp.server.mcpserver.exceptions import ToolError

    vmrun()

    with pytest.raises(ToolError) as excinfo:
        call(server.vm_status, name="definitely-not-a-vm")

    assert "definitely-not-a-vm" in str(excinfo.value)


# --- tools_state ---------------------------------------------------------


def test_tools_state_is_skipped_for_a_stopped_vm(lab, vmrun) -> None:
    """`checkToolsState` on a powered-off VM costs 0.65-3.5s to answer
    `installed`, which means nothing. All 8 VMs in the live lab were powered off
    during M1, so calling it would have added ~15s of pure noise."""
    fake = vmrun()

    result = call(server.vm_status, uuid=DC01_UUID)

    assert result["tools_state"] == "undetermined (vm powered off)"
    assert fake.calls == [["list"]]


def test_tools_state_is_queried_for_a_running_vm(lab, vmrun) -> None:
    """Verified live: a running guest returns `running`, where the field does
    carry meaning."""
    fake = vmrun(list_result=VmrunResult(True, three_running(lab["running_vmx"]), 0))

    result = call(server.vm_status, uuid=DC01_UUID)

    assert result["power_state"] == "running"
    assert result["tools_state"] == "running"
    assert ["checkToolsState", str(lab["dc01"])] in fake.calls


# --- stale registry ------------------------------------------------------


def test_stale_registry_entry_degrades_instead_of_failing(
    lab, vmrun, tmp_path
) -> None:
    """A .vmx deleted without updating the registry must not crash the tool.

    The registry is a cache maintained by the VMware GUI; a missing .vmx is a
    normal condition, and the identity fields are still worth reporting.
    """
    lab["wazuh"].unlink()
    vmrun()

    result = call(server.vm_status, uuid=WAZUH_UUID)

    assert result["vmx_exists"] is False
    assert result["name"] == "wazuh-4.7.5"
    assert "vcpu" not in result, "absent is honest; 0 would read as 'no CPUs'"
    assert result["tools_state"] == "undetermined (vm powered off)"


# --- annotations ---------------------------------------------------------


def test_every_tool_is_described_and_annotated(lab, vmrun) -> None:
    """Every tool has a description and annotations. The read-only claim is now
    per-tool, because as of M2 it is no longer true of the whole surface.

    This started as `test_both_tools_...` asserting exactly `list_vms` and
    `vm_status`, which is a change-detector pointed the wrong way: adding
    `host_resources` had to edit this test to keep it green, and a tool deleted
    from the set would have satisfied it. It then asserted that *every* tool is
    read-only, which was correct while the surface was read-only and became
    false the moment `start_vm` landed: asserting the property over the whole
    set would have failed on a correct implementation. So the read-only claim
    is checked per tool instead -- `test_power.py` covers the mutating tools'
    own annotations. The set is still enumerated from the server, so a tool
    added later is covered without being named here.
    """
    async def go() -> list[Any]:
        return list(await server.mcp.list_tools())

    tools = asyncio.run(go())

    for tool in tools:
        assert tool.description, f"{tool.name} has no description"
        assert tool.annotations is not None, f"{tool.name} has no annotations"
        assert isinstance(tool.annotations.read_only_hint, bool)
        assert isinstance(tool.annotations.destructive_hint, bool)

    read_only = {"list_vms", "vm_status", "host_resources"}
    mutating = {"start_vm", "stop_vm", "restart_vm"}
    assert read_only <= {t.name for t in tools}
    assert mutating <= {t.name for t in tools}

    for tool in tools:
        if tool.name in read_only:
            assert tool.annotations.read_only_hint is True, (
                f"{tool.name} only reads; it must say so"
            )
            assert tool.annotations.destructive_hint is False


def test_vm_status_accepts_either_identifier_and_needs_neither() -> None:
    """Both arguments are nullable and neither is required.

    The model has to be able to send a uuid alone or a name alone. Forcing
    both, or requiring one, pushes it toward inventing a value for the other.
    """
    async def go() -> dict[str, Any]:
        tools = {t.name: t for t in await server.mcp.list_tools()}
        return tools["vm_status"].input_schema

    schema = asyncio.run(go())

    assert set(schema["properties"]) == {"uuid", "name"}
    assert not schema.get("required"), (
        "neither identifier should be required; the tool reports an error when "
        "both are omitted"
    )
    for prop in ("uuid", "name"):
        kinds = {t.get("type") for t in schema["properties"][prop]["anyOf"]}
        assert kinds == {"string", "null"}, f"{prop} must accept null"


def test_list_vms_takes_no_arguments() -> None:
    async def go() -> dict[str, Any]:
        tools = {t.name: t for t in await server.mcp.list_tools()}
        return tools["list_vms"].input_schema

    assert asyncio.run(go())["properties"] == {}