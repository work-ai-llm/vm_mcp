"""VMware Workstation registry (.vmls) reading and VM identity resolution.

This module is the answer to "which VMs exist on this machine", and there is
only one good source for that: the registry the VMware GUI itself reads to
populate its library.

    %APPDATA%\\VMware\\inventory.vmls

The alternatives were measured and rejected:

* `vmrun list` enumerates the *running* set only. With the lab powered off it
  returns zero VMs, and the actual count is eight. It cannot answer the
  question.
* Globbing the filesystem for `*.vmx` finds VMs that were deleted from VMware
  years ago, misses VMs stored outside the searched tree, and carries no
  identity and no power state. It is not a registry.
* A hardcoded allowlist is wrong for a shared server. It encodes one operator's
  lab layout into an artifact other people run, and reports "unknown VM" for
  every VM the caller actually owns.

Format notes, all verified against the live file rather than assumed:

* It is a flat `key = "value"` list, self-describing with a leading
  `.encoding` directive that currently reads `windows-1251`. Decoding is
  therefore driven by that directive. Assuming UTF-8 would mojibake any
  non-ASCII display name, and hardcoding cp1251 would break on a machine whose
  locale writes something else.
* Identity lives in `vmlist<N>.config` (absolute .vmx path),
  `vmlist<N>.DisplayName`, and `vmlist<N>.UUID`. Six of fourteen vmlist blocks
  have an empty config; they are stubs and are skipped.
* The file also carries free-text `guest` and `notes` fields. Those are
  user-typed and rot. Paired by each block's own `index<N>.id` path against the
  `.vmx` `guestos`, three of the eight VMs on this host carry a guest label that
  is simply wrong: `GOAD-DC01`, `GOAD-DC02` and `GOAD-SRV02` are all labelled
  "windows server 2016" while both their `guestos` key and their filenames say
  Server 2019. This module reads only machine-written identity fields and never
  those.

Resolution policy
-----------------
A caller supplies an identifier; this module decides what it points at. That
mapping is the security boundary for every future mutating tool, so the rules
are conservative:

* UUID first, exact after normalization. It is the only unambiguous key: it is
  written into the `.vmx` at VM creation and survives a display-name rename.
* Display name only as a convenience fallback, and an ambiguous name is an
  error listing candidates rather than a guess.
* The registry is read once and cached. See `refresh()`.

The UUID comparison normalizes away case and separators because the registry
writes `56 4d f4 8b bf be 94 a5-...` while a caller may pass the dashed form.

Two distinct UUIDs exist per Vagrant VM and must not be confused. This module
uses the VM's own `uuid.bios`. The dashed UUID appearing in the *path*
(`vmware_desktop\\7119ad91-edde-...`) is Vagrant's workspace directory name; it
changes on a Vagrant rebuild and means nothing outside that folder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from vm_mcp.vmrun import normalize_uuid

__all__ = [
    "RegisteredVm",
    "RosterSnapshot",
    "RosterError",
    "AmbiguousName",
    "UnknownVm",
    "inventory_path",
    "parse_inventory",
    "load_roster",
    "refresh",
    "resolve",
]


class RosterError(Exception):
    """The registry could not be read or is unusable.

    Failing closed is deliberate. A server that cannot enumerate VMs must not
    fall back to "no VMs known" quietly in a way that looks like an empty lab;
    and it must certainly not fail open by accepting an unverified identifier.
    """


class UnknownVm(RosterError):
    """No registered VM matches the supplied identifier."""


class AmbiguousName(RosterError):
    """A display name matches more than one registered VM.

    Carries the candidates so the caller can report them instead of silently
    picking one. An agent asked about "Windows 10" when two VMs are called
    "Windows 10" must not receive a confident answer about the wrong one.
    """

    def __init__(self, name: str, candidates: list[str]) -> None:
        self.name = name
        self.candidates = candidates
        joined = ", ".join(candidates)
        super().__init__(
            f"display name {name!r} matches {len(candidates)} VMs: {joined}. "
            "Identify the VM by uuid instead."
        )


@dataclass(frozen=True)
class RegisteredVm:
    """One VM as the registry records it.

    Attributes:
        name: Display name from the registry. Renamable, possibly ambiguous.
        uuid: Hardware UUID, equal to the `.vmx` `uuid.bios`. Stable across a
            rename; not stable across destroy-and-recreate.
        vmx: Absolute path to the `.vmx` file. May not exist on disk if the VM
            was moved or deleted without updating the registry.
    """

    name: str
    uuid: str
    vmx: str

    @property
    def normalized_uuid(self) -> str:
        return normalize_uuid(self.uuid)


@dataclass(frozen=True)
class RosterSnapshot:
    """Result of one registry read.

    Attributes:
        vms: Registered VMs with a non-empty path, in registry order.
        error: Why the read failed, or None. Present so a caller can report
            "the registry is unreadable" rather than "there are no VMs", which
            are very different facts.
    """

    vms: tuple[RegisteredVm, ...]
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def inventory_path() -> Path:
    """Path to this user's VMware registry.

    Derived from the user profile rather than hardcoded, so the server works
    for whoever runs it -- which is the entire premise of reading the registry
    instead of shipping a static allowlist.
    """
    return Path.home() / "AppData" / "Roaming" / "VMware" / "inventory.vmls"


# `.encoding = "windows-1251"` -- the file states its own encoding.
_ENCODING_RE = re.compile(r'^\s*\.encoding\s*=\s*"([^"]*)"', re.MULTILINE)

# Identity fields only. `guest` and `notes` are deliberately absent: they are
# free text, they rot, and they were verified wrong on 7 of 8 VMs.
_VMLIST_RE = re.compile(r'^(vmlist\d+)\.(config|DisplayName|UUID)\s*=\s*"(.*)"\s*$')

# Fallback when the encoding directive is missing or names a codec we lack.
_FALLBACK_ENCODING = "cp1251"

# A VMware hardware UUID is 16 bytes, written `56 4d f4 8b bf be 94 a5-f8 b5 17
# 60 df 89 9e 33` — 32 hex digits once separators are removed. The length is
# what distinguishes a UUID from a display name that happens to contain hex
# letters; see `_is_uuid_shaped`.
_UUID_HEX_DIGITS = 32


def _is_uuid_shaped(value: str) -> bool:
    """True if `value` is a plausible VM UUID once separators are removed.

    Needed because `normalize_uuid` cannot tell the two apart on its own:
    "provider: GOAD-DC01" normalizes to "deadc01", which is non-empty, so a
    naive "is there anything left after stripping?" test routes every display
    name into the UUID branch and then fails there.
    """
    return len(normalize_uuid(value)) == _UUID_HEX_DIGITS


def parse_inventory(raw: bytes) -> RosterSnapshot:
    """Parse raw `inventory.vmls` bytes into registered VMs.

    Tolerant by construction: an unparseable line is skipped rather than
    fatal, because a VMware update that adds a key must not break the server.

    Args:
        raw: File contents exactly as read from disk.

    Returns:
        A RosterSnapshot. `error` is set only if the bytes are unusable as a
        registry at all (no recognizable vmlist blocks, or no decodable
        encoding).
    """
    match = _ENCODING_RE.search(raw.decode("latin-1", errors="replace"))
    encoding = match.group(1).strip().lower() if match else _FALLBACK_ENCODING

    try:
        text = raw.decode(encoding, errors="replace")
    except LookupError:
        # An unknown codec name in the directive must not be fatal; cp1251 is
        # the observed value and latin-1 never fails.
        text = raw.decode(_FALLBACK_ENCODING, errors="replace")

    vms: list[RegisteredVm] = []
    pending: dict[str, dict[str, str]] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        found = _VMLIST_RE.match(line)
        if found is None:
            continue

        block, field, value = found.groups()
        slot = pending.setdefault(block, {})
        slot[field] = value

        # A block is only complete once UUID arrives, which is where the real
        # entries end and the stubs begin.
        if field != "UUID":
            continue

        pending.pop(block, None)
        config = slot.get("config", "").strip()
        if not config:
            # Stub entry: present in the file, no VM behind it.
            continue

        vms.append(
            RegisteredVm(
                name=slot.get("DisplayName", "").strip(),
                uuid=slot.get("UUID", "").strip(),
                vmx=config,
            )
        )

    if not vms:
        return RosterSnapshot(
            vms=(),
            error=(
                "no VM entries found in the VMware registry; the file may be "
                "from a newer VMware release with a changed format"
            ),
        )

    return RosterSnapshot(vms=tuple(vms))


def load_roster(path: Path | None = None) -> RosterSnapshot:
    """Read and parse the registry from disk."""
    source = Path(path) if path is not None else inventory_path()

    try:
        raw = source.read_bytes()
    except FileNotFoundError:
        return RosterSnapshot(
            vms=(),
            error=(
                f"VMware registry not found at {source}. VMware Workstation "
                "may not be installed for this user."
            ),
        )
    except OSError as exc:
        return RosterSnapshot(vms=(), error=f"could not read {source}: {exc}")

    return parse_inventory(raw)


_cache: RosterSnapshot | None = None


def refresh(path: Path | None = None) -> RosterSnapshot:
    """Read the registry and replace the cached snapshot.

    Read once at startup and cached, deliberately. A long-lived HTTP server
    would otherwise either hold a stale answer indefinitely or re-read the file
    on every call and pay for it. Explicit `refresh()` is the escape hatch for
    the case where someone registers a new VM and wants the server to notice.
    """
    global _cache
    _cache = load_roster(path)
    return _cache


def _snapshot() -> RosterSnapshot:
    global _cache
    if _cache is None:
        _cache = load_roster()
    return _cache


def resolve(
    identifier: str | None = None,
    *,
    uuid: str | None = None,
    name: str | None = None,
) -> RegisteredVm:
    """Map a caller-supplied identifier to exactly one registered VM.

    Args:
        identifier: Either a UUID or a display name. Tried as UUID first, then
            as a name.
        uuid: Explicit UUID form of the same thing, takes precedence over
            `name`.
        name: Explicit display-name form.

    Returns:
        The single matching RegisteredVm.

    Raises:
        UnknownVm: Nothing matched, or the registry is unusable.
        AmbiguousName: A display name matched more than one VM.
    """
    roster = _snapshot()
    if not roster.ok:
        raise RosterError(roster.error or "registry unavailable")

    explicit_uuid = uuid
    explicit_name = name

    # A bare `identifier` is tried as a UUID and then as a name, so it has to be
    # classified rather than assumed.
    wanted_uuid = explicit_uuid or identifier
    wanted_name = explicit_name or (
        identifier if explicit_uuid is None and explicit_name is None else None
    )

    # Only treat something as a UUID if it is actually UUID-shaped. Stripping
    # non-hex characters is not enough: "provider: GOAD-DC01" reduces to
    # "deadc01", which is non-empty and would send a display name down the UUID
    # path and fail it there.
    if wanted_uuid and _is_uuid_shaped(wanted_uuid):
        target = normalize_uuid(wanted_uuid)
        for vm in roster.vms:
            if vm.normalized_uuid == target:
                return vm
        # A UUID-shaped identifier that matched nothing is an error rather than
        # a fallback to name matching. A caller who mistyped one character gets
        # told, instead of silently receiving a report about a different VM.
        raise UnknownVm(f"no registered VM with uuid {wanted_uuid!r}")

    if explicit_uuid is not None:
        # Explicitly asked for by UUID but the value is not a UUID at all.
        raise UnknownVm(f"{explicit_uuid!r} is not a VM UUID")

    if not wanted_name:
        raise UnknownVm("no VM identifier supplied")

    needle = wanted_name.strip()
    if not needle:
        raise UnknownVm("empty VM identifier")

    # Exact display-name match, then case-insensitive. Two tiers so a name that
    # is unique up to case resolves without ambiguity.
    exact = [vm for vm in roster.vms if vm.name == needle]
    if len(exact) == 1:
        return exact[0]

    folded = [vm for vm in roster.vms if vm.name.casefold() == needle.casefold()]
    if len(folded) == 1:
        return folded[0]
    if len(folded) > 1:
        raise AmbiguousName(needle, [vm.name for vm in folded])

    if exact:
        raise AmbiguousName(needle, [vm.name for vm in exact])

    raise UnknownVm(f"no registered VM named {needle!r}")