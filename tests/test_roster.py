"""Tests for the VMware registry reader and VM identity resolution.

Nothing here touches VMware. The registry is a flat text file, so the tests
feed it bytes and assert on what comes back. The fixture reproduces the shape
of the live file, including the parts that are easy to get wrong:

* a `.encoding` directive, currently `windows-1251`. The live file contains a
  non-ASCII display name, so a UTF-8 assumption would be caught here rather
  than in production.
* `vmlist` blocks whose `config` is empty. The live registry has 14 blocks and
  6 of them are stubs with no VM behind them; counting all 14 would report
  twice as many VMs as exist.
* `index` blocks carrying the free-text `guest` and `notes` metadata. Those are
  deliberately not read, and there is a test that pins that decision.

Run:
    .venv\\Scripts\\python.exe -m pytest tests/test_roster.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vm_mcp import roster
from vm_mcp.vmrun import normalize_uuid

# A path containing a non-ASCII segment. Encoded cp1251 this is "тест"
# (Cyrillic); decoded as UTF-8 it becomes mojibake, which is exactly the bug the
# `.encoding` directive exists to prevent.
CYRILLIC = "тест"
_NON_ASCII_NAME = f"VM-{CYRILLIC}"

VMS = {
    "dc01": ("provider: GOAD-DC01", "56 4d f4 8b bf be 94 a5-f8 b5 17 60 df 89 9e 33"),
    "dc02": ("provider: GOAD-DC02", "56 4d 7e 53 a7 bf 0d 82-aa 77 02 ce 5a 87 ad bf"),
    "wazuh": ("wazuh-4.7.5", "dd 00 00 00 00 00 00 00-00 00 00 00 00 00 00 04"),
    "dup_a": ("Windows 10", "aa 00 00 00 00 00 00 00-00 00 00 00 00 00 00 01"),
    "dup_b": ("Windows 10", "bb 00 00 00 00 00 00 00-00 00 00 00 00 00 00 02"),
    "cyr": (_NON_ASCII_NAME, "cc 00 00 00 00 00 00 00-00 00 00 00 00 00 00 03"),
}

# Registered after the server is already running, to prove there is no cache.
NEW_UUID = "ee 00 00 00 00 00 00 00-00 00 00 00 00 00 00 05"

GOAD_ROOT = r"D:\vms\work_AD\goad\workspace\560030-goad-vmware\provider\.vagrant\machines"


def vmx_path(key: str) -> str:
    if key == "dc01":
        return rf"{GOAD_ROOT}\GOAD-DC01\vmware_desktop\7119ad91-edde-47d2-8b3e-ab6a8243183d\WindowsServer2019.vmx"
    if key == "dc02":
        return rf"{GOAD_ROOT}\GOAD-DC02\vmware_desktop\16227c43-505c-4c33-aae8-1873fba30582\WindowsServer2019.vmx"
    if key == "wazuh":
        return rf"{GOAD_ROOT}\wazuh-4.7.5\vmware_desktop\a3f1c0de-1111-2222-3333-444455556666\wazuh-4.7.5.vmx"
    if key == "cyr":
        return f"C:\\VMs\\{CYRILLIC}\\{_NON_ASCII_NAME}.vmx"
    return f"C:\\VMs\\{key}\\{key}.vmx"


def build_inventory(
    *,
    include_stubs: bool = True,
    encoding: str = "windows-1251",
    extra_entries: dict[str, tuple[str, str]] | None = None,
) -> bytes:
    """Build a byte-exact inventory.vmls equivalent.

    Block layout mirrors the live file: config, DisplayName, ParentID, ItemID,
    SeqID, IsFavorite, IsClone, CfgVersion, State, UUID, IsCfgPathNormalized.

    Args:
        include_stubs: Append the empty-config blocks the live file carries.
        encoding: The `.encoding` directive value.
        extra_entries: Additional `name -> (uuid, vmx)` entries, appended after
            the fixed ones. Used to simulate a VM registered after startup.
    """
    out: list[str] = [f'.encoding = "{encoding}"']

    # (display name, uuid, vmx) for every real entry.
    entries: list[tuple[str, str, str]] = [
        (name, uuid, vmx_path(key)) for key, (name, uuid) in VMS.items()
    ]
    entries += [
        (name, uuid, vmx) for name, (uuid, vmx) in (extra_entries or {}).items()
    ]

    for n, (name, uuid, config) in enumerate(entries, start=2):
        out += [
            f'vmlist{n}.config = "{config}"',
            f'vmlist{n}.DisplayName = "{name}"',
            f'vmlist{n}.ParentID = "0"',
            f'vmlist{n}.ItemID = "{n}"',
            f'vmlist{n}.SeqID = "0"',
            f'vmlist{n}.IsFavorite = "FALSE"',
            f'vmlist{n}.IsClone = "FALSE"',
            f'vmlist{n}.CfgVersion = "8"',
            f'vmlist{n}.State = "normal"',
            f'vmlist{n}.UUID = "{uuid}"',
            f'vmlist{n}.IsCfgPathNormalized = "TRUE"',
        ]

    if include_stubs:
        # Blocks with an empty config: present in the file, no VM behind them.
        # Numbered well past the real entries so they cannot collide with one.
        for n in (20, 21, 22, 23, 24, 25):
            out += [
                f'vmlist{n}.config = ""',
                f'vmlist{n}.DisplayName = ""',
                f'vmlist{n}.ParentID = "0"',
                f'vmlist{n}.ItemID = "{n}"',
                f'vmlist{n}.State = "normal"',
                f'vmlist{n}.UUID = ""',
            ]

    # Free-text metadata that is verified wrong on the live host and must never
    # be read. Included here so the "must be ignored" test has something to
    # ignore.
    out += [
        'index2.field0.name = "guest"',
        'index2.field0.value = "windows server 2016"',
        'index2.field0.default = "TRUE"',
        'index2.field1.name = "notes"',
        'index2.field1.value = "a note"',
        'index2.field1.default = "TRUE"',
        f'index2.id = "{vmx_path("dc01")}"',
        'index2.field.count = "2"',
        'index.count = "8"',
    ]

    return "\r\n".join(out).encode(encoding, errors="replace")


@pytest.fixture
def loaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> roster.RosterSnapshot:
    """A registry loaded from the fixture."""
    registry_file = tmp_path / "inventory.vmls"
    registry_file.write_bytes(build_inventory())

    monkeypatch.setattr(roster, "inventory_path", lambda: registry_file)

    return roster.registry()


# --- parsing -------------------------------------------------------------


def test_parses_only_vms_with_a_config(loaded: roster.RosterSnapshot) -> None:
    """Stub blocks must not become VMs.

    The live registry has 14 vmlist blocks for 8 VMs. Counting blocks instead of
    entries would report 14 VMs, 6 of which do not exist.
    """
    assert loaded.ok
    assert len(loaded.vms) == len(VMS)
    assert {vm.name for vm in loaded.vms} == {name for name, _ in VMS.values()}


def test_stubs_are_skipped_when_present() -> None:
    """The same registry without stubs yields the same VM count."""
    parsed = roster.parse_inventory(build_inventory(include_stubs=False))
    assert len(parsed.vms) == len(VMS)


def test_reads_the_declared_encoding_not_utf8() -> None:
    """A non-ASCII display name survives only if `.encoding` is honoured.

    Decoding these bytes as UTF-8 raises or produces mojibake, so this test is
    the one that would catch a regression to a UTF-8 assumption.
    """
    parsed = roster.parse_inventory(build_inventory())

    assert any(CYRILLIC in vm.name for vm in parsed.vms), (
        "the cp1251 display name did not round-trip; the .encoding directive "
        "was probably ignored"
    )


def test_registry_with_no_vms_is_an_error_not_an_empty_lab(
    tmp_path: Path,
) -> None:
    """An unreadable registry must be distinguishable from an empty one.

    "VMware is not installed" and "the lab has no VMs" are different facts, and
    a caller that cannot tell them apart will confidently report a wrong one.
    """
    empty = tmp_path / "inventory.vmls"
    empty.write_bytes(b'.encoding = "windows-1251"\n')

    parsed = roster.load_roster(empty)

    assert parsed.vms == ()
    assert not parsed.ok
    assert parsed.error


def test_missing_registry_reports_its_path(tmp_path: Path) -> None:
    parsed = roster.load_roster(tmp_path / "nope.vmls")
    assert not parsed.ok
    assert "not found" in parsed.error.lower()


def test_garbage_does_not_raise(tmp_path: Path) -> None:
    """A format change in a future VMware release must not crash the server."""
    junk = tmp_path / "inventory.vmls"
    junk.write_bytes(b"\x00\x01garbage\xff\nvmlist?.config = \"??\"\r\nno equals sign\n")

    parsed = roster.load_roster(junk)  # must not raise

    assert parsed.vms == ()
    assert not parsed.ok


def test_wrong_guest_metadata_is_not_read(loaded: roster.RosterSnapshot) -> None:
    """`RegisteredVm` carries identity only: path, name, UUID.

    The registry's `guest` field is user-typed free text and is wrong on three
    of the eight VMs on the live host: GOAD-DC01, GOAD-DC02 and GOAD-SRV02 are
    all labelled "windows server 2016" when both their `.vmx` `gustos` key and
    their filenames say Server 2019. If a future change starts reading it, that
    stale label becomes a confident wrong answer about a guest OS.
    """
    for vm in loaded.vms:
        assert set(vars(vm)) == {"name", "uuid", "vmx"}
        assert "windows server 2016" not in vm.name


# --- resolution ----------------------------------------------------------


def test_resolves_by_uuid(loaded: roster.RosterSnapshot) -> None:
    vm = roster.resolve(uuid=VMS["dc01"][1])
    assert vm.name == "provider: GOAD-DC01"


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param("564df48bbfbe94a5f8b51760df899e33", id="no-separators"),
        pytest.param("56 4d f4 8b bf be 94 a5-f8 b5 17 60 df 89 9e 33", id="spaced"),
        pytest.param("564DF48B-BFBE-94A5-F8B5-1760DF899E33", id="dashed-upper"),
    ],
)
def test_uuid_comparison_ignores_case_and_separators(
    loaded: roster.RosterSnapshot, variant: str
) -> None:
    """An agent copying a UUID out of `list_vms` should not have to preserve
    its exact spacing. Case and separators are not significant."""
    vm = roster.resolve(uuid=variant)
    assert vm.name == "provider: GOAD-DC01"


def test_falls_back_to_name(loaded: roster.RosterSnapshot) -> None:
    vm = roster.resolve(name="provider: GOAD-DC02")
    assert vm.name == "provider: GOAD-DC02"


def test_name_match_is_case_insensitive(loaded: roster.RosterSnapshot) -> None:
    vm = roster.resolve(name="PROVIDER: GOAD-DC02")
    assert vm.name == "provider: GOAD-DC02"


def test_positional_identifier_tries_uuid_then_name(loaded: roster.RosterSnapshot) -> None:
    """A bare identifier works either way, which is what an agent will try."""
    by_uuid = roster.resolve(VMS["dc01"][1])
    by_name = roster.resolve("provider: GOAD-DC01")
    assert by_uuid.uuid == by_name.uuid


def test_ambiguous_name_is_an_error_listing_candidates(
    loaded: roster.RosterSnapshot,
) -> None:
    """Two VMs can share a display name. Picking one silently is the failure
    mode: the caller would get a confident answer about the wrong machine."""
    with pytest.raises(roster.AmbiguousName) as excinfo:
        roster.resolve(name="Windows 10")

    assert len(excinfo.value.candidates) == 2
    assert "uuid" in str(excinfo.value).lower()


def test_unknown_uuid_does_not_fall_through_to_a_name_lookup(
    loaded: roster.RosterSnapshot,
) -> None:
    """A UUID-shaped identifier that matches nothing is an error, not a name
    search. Otherwise a typo silently reports on some other VM."""
    with pytest.raises(roster.UnknownVm):
        roster.resolve(uuid="de ad be ef 00 00 00 00-00 00 00 00 00 00 00 ff")


def test_unknown_name_raises(loaded: roster.RosterSnapshot) -> None:
    with pytest.raises(roster.UnknownVm):
        roster.resolve(name="no-such-vm")


def test_empty_identifier_raises(loaded: roster.RosterSnapshot) -> None:
    with pytest.raises(roster.UnknownVm):
        roster.resolve(name="   ")


def test_unavailable_registry_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With an unreadable registry, resolution must refuse rather than accept.

    This is the security boundary for every future mutating tool: the safe
    failure is "I will not touch anything", not "no match, so try this other
    thing".
    """
    monkeypatch.setattr(roster, "inventory_path", lambda: tmp_path / "gone.vmls")

    with pytest.raises(roster.RosterError):
        roster.resolve(name="provider: GOAD-DC01")


# --- freshness ------------------------------------------------------------


def test_a_vm_registered_after_startup_is_visible(
    loaded: roster.RosterSnapshot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No cache: a VM registered while the server is running resolves at once.

    The tool that previously cached this returned a stale roster, so
    `list_vms` could show a VM that `vm_status` then refused. Re-reading costs
    under a millisecond and removes a whole class of "it depends what you called
    first" bugs.
    """
    registry_file = tmp_path / "inventory.vmls"
    assert loaded.ok

    registry_file.write_bytes(
        build_inventory(extra_entries={"NewVM": (NEW_UUID, r"C:\vm\NewVM.vmx")})
    )

    found = roster.resolve(name="NewVM")
    assert found.normalized_uuid == normalize_uuid(NEW_UUID)


# --- name matching --------------------------------------------------------


def test_name_without_the_registry_prefix_resolves(
    loaded: roster.RosterSnapshot,
) -> None:
    """`GOAD-DC01` must find the VM the registry calls `provider: GOAD-DC01`.

    Refusing correct input because the registry carries a Vagrant prefix makes
    the tool unusable: the caller has done everything right and is still told
    the VM does not exist.
    """
    assert roster.resolve(name="GOAD-DC01").normalized_uuid == normalize_uuid(VMS["dc01"][1])


def test_prefix_stripped_name_is_case_insensitive(
    loaded: roster.RosterSnapshot,
) -> None:
    assert roster.resolve(name="goad-dc01").normalized_uuid == normalize_uuid(VMS["dc01"][1])


def test_vmx_filename_stem_resolves(
    loaded: roster.RosterSnapshot,
) -> None:
    """The `.vmx` stem is the label a user sees in Explorer, often not the
    display name at all."""
    stem = Path(vmx_path("cyr")).stem
    assert roster.resolve(name=stem).normalized_uuid == normalize_uuid(VMS["cyr"][1])


def test_shared_vmx_stem_is_ambiguous_not_a_guess(
    loaded: roster.RosterSnapshot,
) -> None:
    """Both GOAD domain controllers ship a `WindowsServer2019.vmx`.

    Matching the filename stem therefore cannot identify one of them. Picking
    the first would answer about an arbitrary machine, which for a tool that
    will eventually power VMs off is the wrong thing to do confidently.
    """
    with pytest.raises(roster.AmbiguousName) as excinfo:
        roster.resolve(name="WindowsServer2019")

    assert len(excinfo.value.candidates) == 2


def test_unique_substring_resolves(loaded: roster.RosterSnapshot) -> None:
    """A fragment is enough when only one VM can match."""
    assert roster.resolve(name="wazuh").normalized_uuid == normalize_uuid(VMS["wazuh"][1])


def test_ambiguous_substring_is_an_error_not_a_guess(
    loaded: roster.RosterSnapshot,
) -> None:
    """`DC0` is a substring of every domain controller. Picking the first match
    would answer about an arbitrary one."""
    with pytest.raises(roster.AmbiguousName) as excinfo:
        roster.resolve(name="DC0")

    assert len(excinfo.value.candidates) > 1


def test_very_short_query_does_not_fuzzy_match(
    loaded: roster.RosterSnapshot,
) -> None:
    """`01` is a substring of half the lab, so below the length floor a query
    only matches exactly."""
    with pytest.raises(roster.UnknownVm):
        roster.resolve(name="01")


# --- identifier handling --------------------------------------------------


def test_uuid_passed_as_name_still_resolves(
    loaded: roster.RosterSnapshot,
) -> None:
    """A caller who pastes a uuid into `name` should get the VM, not a
    'no such display name' error about a perfectly good uuid."""
    assert roster.resolve(name=VMS["dc01"][1]).normalized_uuid == normalize_uuid(VMS["dc01"][1])


def test_unknown_name_error_lists_what_is_registered(
    loaded: roster.RosterSnapshot,
) -> None:
    """An error that names the alternatives is the difference between one retry
    and a dead end."""
    with pytest.raises(roster.UnknownVm) as excinfo:
        roster.resolve(name="no-such-vm")

    message = str(excinfo.value)
    assert "provider: GOAD-DC01" in message
    assert "list_vms" in message


def test_agreeing_uuid_and_name_are_accepted(
    loaded: roster.RosterSnapshot,
) -> None:
    """Redundant identifiers that agree are not an error; some clients send
    both for safety."""
    vm = roster.resolve(uuid=VMS["dc01"][1], name="GOAD-DC01")
    assert vm.normalized_uuid == normalize_uuid(VMS["dc01"][1])


def test_uuid_and_name_pointing_at_different_vms_is_an_error(
    loaded: roster.RosterSnapshot,
) -> None:
    """Silently preferring the uuid would discard half the caller's intent, and
    this resolution is the trust boundary future power tools will sit behind."""
    with pytest.raises(roster.IdentifierMismatch) as excinfo:
        roster.resolve(uuid=VMS["dc01"][1], name="wazuh-4.7.5")

    message = str(excinfo.value)
    assert "provider: GOAD-DC01" in message
    assert "wazuh-4.7.5" in message


# --- error taxonomy -------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(roster.UnknownVm, id="unknown"),
        pytest.param(roster.AmbiguousName, id="ambiguous"),
        pytest.param(roster.IdentifierMismatch, id="mismatch"),
    ],
)
def test_every_resolution_error_is_catchable_as_roster_error(
    exc: type[Exception],
) -> None:
    """Regression guard for a real bug.

    This module briefly defined `RosterError` twice. `IdentifierMismatch`
    subclassed the first definition; the second then shadowed the name. Every
    direct test still passed, because `pytest.raises(roster.IdentifierMismatch)`
    compares the concrete class -- but `except roster.RosterError` in the server
    no longer matched it, so a caller got a generic framework error instead of
    the message explaining which two identifiers disagreed.

    Asserting the hierarchy directly is the only thing that catches it.
    """
    assert issubclass(exc, roster.RosterError)


def test_normalize_uuid_strips_every_separator() -> None:
    assert normalize_uuid("56 4d:f4-8b.BF") == "564df48bbf"