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
    "dup_a": ("Windows 10", "aa 00 00 00 00 00 00 00-00 00 00 00 00 00 00 01"),
    "dup_b": ("Windows 10", "bb 00 00 00 00 00 00 00-00 00 00 00 00 00 00 02"),
    "cyr": (_NON_ASCII_NAME, "cc 00 00 00 00 00 00 00-00 00 00 00 00 00 00 03"),
}

GOAD_ROOT = r"D:\vms\work_AD\goad\workspace\560030-goad-vmware\provider\.vagrant\machines"


def vmx_path(key: str) -> str:
    if key == "dc01":
        return rf"{GOAD_ROOT}\GOAD-DC01\vmware_desktop\7119ad91-edde-47d2-8b3e-ab6a8243183d\WindowsServer2019.vmx"
    if key == "dc02":
        return rf"{GOAD_ROOT}\GOAD-DC02\vmware_desktop\16227c43-505c-4c33-aae8-1873fba30582\WindowsServer2019.vmx"
    if key == "cyr":
        return f"C:\\VMs\\{CYRILLIC}\\{_NON_ASCII_NAME}.vmx"
    return f"C:\\VMs\\{key}\\{key}.vmx"


def build_inventory(*, include_stubs: bool = True, encoding: str = "windows-1251") -> bytes:
    """Build a byte-exact inventory.vmls equivalent.

    Block layout mirrors the live file: config, DisplayName, ParentID, ItemID,
    SeqID, IsFavorite, IsClone, CfgVersion, State, UUID, IsCfgPathNormalized.
    """
    out: list[str] = [f'.encoding = "{encoding}"']

    for n, (key, (name, uuid)) in enumerate(VMS.items(), start=2):
        out += [
            f'vmlist{n}.config = "{vmx_path(key)}"',
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
        for n in (3, 4, 5, 6, 7, 14):
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
    """A registry loaded from the fixture, with the module cache pointed at it."""
    registry_file = tmp_path / "inventory.vmls"
    registry_file.write_bytes(build_inventory())

    monkeypatch.setattr(roster, "inventory_path", lambda: registry_file)
    monkeypatch.setattr(roster, "_cache", None, raising=False)

    return roster.refresh()


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


def test_uuid_wins_over_name(loaded: roster.RosterSnapshot) -> None:
    """An explicit uuid is never second-guessed by a name."""
    vm = roster.resolve(uuid=VMS["dc01"][1], name="provider: GOAD-DC02")
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


def test_unavailable_registry_fails_closed(loaded: roster.RosterSnapshot) -> None:
    """With an unreadable registry, resolution must refuse rather than accept.

    This is the security boundary for every future mutating tool: the safe
    failure is "I will not touch anything", not "no match, so try this other
    thing".
    """
    broken = roster.RosterSnapshot(vms=(), error="registry unreadable")
    roster._cache = broken  # noqa: SLF001 — deliberate cache poisoning

    with pytest.raises(roster.RosterError):
        roster.resolve(name="provider: GOAD-DC01")


# --- caching -------------------------------------------------------------


def test_refresh_replaces_the_cache(loaded: roster.RosterSnapshot) -> None:
    """Read once at startup, cached -- with an explicit refresh as the escape
    hatch for a VM registered after the server started."""
    assert roster._snapshot() is roster._snapshot()  # noqa: SLF001

    again = roster.refresh()

    assert again.ok
    assert len(again.vms) == len(VMS)


def test_normalize_uuid_strips_every_separator() -> None:
    assert normalize_uuid("56 4d:f4-8b.BF") == "564df48bbf"