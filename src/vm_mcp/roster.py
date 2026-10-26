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
  Never falls back to name matching, so a mistyped UUID is an error rather than
  a report about the wrong machine.
* Names are matched loosely, because refusing a correct-but-differently-spelled
  name makes a tool unusable rather than safe. Three tiers, each looser than
  the last, stopping at the first that matches: the exact registry name; any
  accepted alias (prefix-stripped, or the `.vmx` filename stem), case-folded;
  then a unique substring. An ambiguous match is an error listing candidates,
  never a guess.
* A UUID passed in the `name` argument is still recognized as a UUID. A caller
  who pastes a uuid into the wrong argument should get the right VM.
* Supplying a uuid and a name that disagree is an error. Quietly preferring one
  discards half the caller's intent.
* Failures list what *is* registered. An error that names the alternatives is
  the difference between one retry and a dead end.

Freshness: the registry is re-read on every call. It is a 7 KB file and reads in
under a millisecond; caching it bought nothing and made `list_vms` and
`vm_status` able to disagree about which VMs exist.

The UUID comparison normalizes away case and separators because the registry
writes `56 4d f4 8b bf be 94 a5-...` while a caller may pass the dashed form.

Two distinct UUIDs exist per Vagrant VM and must not be confused. This module
uses the VM's own `uuid.bios`. The dashed UUID appearing in the *path*
(`vmware_desktop\\7119ad91-edde-...`) is Vagrant's workspace directory name; it
changes on a Vagrant rebuild and means nothing outside that folder.
"""

from __future__ import annotations

import difflib
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from vm_mcp.vmrun import normalize_uuid

__all__ = [
    "RegisteredVm",
    "RosterSnapshot",
    "RosterError",
    "AmbiguousName",
    "UnknownVm",
    "IdentifierMismatch",
    "inventory_path",
    "parse_inventory",
    "load_roster",
    "registry",
    "resolve",
]


# Vagrant writes display names as "provider: GOAD-DC01". A human reading about
# the lab writes "GOAD-DC01", and an agent that read a document mentioning
# GOAD-DC01 will pass that. Requiring the exact registry spelling makes the tool
# fail on correct input, which is the worst failure mode there is: the caller
# has done everything right and still gets told no.
_PREFIX_RE = re.compile(r"^[A-Za-z][\w-]*:\s*")

# A name query shorter than this is not used for substring matching, because
# "01" is a substring of half the lab.
_MIN_SUBSTRING = 3

# Enough alternatives to name in an error: enough to be actionable, few enough
# that the message stays readable on a host with twenty VMs.
_MAX_SUGGESTIONS = 12


class RosterError(Exception):
    """The registry could not be read or is unusable.

    Failing closed is deliberate. A server that cannot enumerate VMs must not
    fall back to "no VMs known" quietly in a way that looks like an empty lab;
    and it must certainly not fail open by accepting an unverified identifier.
    """


class UnknownVm(RosterError):
    """No registered VM matches the supplied identifier.

    The message is tailored to which kind of identifier failed. A name that
    matched nothing gets near-miss suggestions, because the caller's problem is
    a spelling. A UUID that matched nothing gets told its length and pointed at
    `list_vms`, because the caller's problem is that they pasted a fragment --
    and telling a caller who just supplied a uuid to "use a uuid" is absurd.
    """

    def __init__(
        self,
        query: str,
        candidates: Sequence[str],
        *,
        as_uuid: bool = False,
        uuid_text: str = "",
        name_text: str = "",
    ) -> None:
        self.query = query
        self.candidates = list(candidates)

        # `query` already carries its own quoting (e.g. `name 'GOAD-DC0'`), so it
        # is interpolated rather than repr'd -- otherwise the message reads
        # `no registered VM matches "name 'GOAD-DC0'"`.
        message = f"no registered VM matches {query}"

        if as_uuid:
            # Length is the actionable fact. A VMware UUID is 16 bytes rendered as
            # 32 hex digits, with the registry's own spacing varying; anything
            # shorter is a truncated paste or a typo, and saying so saves the
            # caller from re-reading the whole roster looking for a near miss.
            digits = len(normalize_uuid(uuid_text))
            message += (
                f". That is {digits} hex characters; a VM uuid is 32. "
                "Call list_vms for the registered uuids."
            )
            super().__init__(message)
            return

        if not candidates:
            message += ". No VMs are registered for this user."
        else:
            close = difflib.get_close_matches(
                name_text.strip().casefold(),
                [c.casefold() for c in candidates],
                n=_MAX_SUGGESTIONS,
                cutoff=0.5,
            )
            if close:
                # Close matches are the answer. Appending the full roster on top
                # is noise, and produced "Did you mean: X?. Registered VMs: ..."
                by_folded = {c.casefold(): c for c in candidates}
                message += ". Did you mean: " + ", ".join(
                    by_folded[c] for c in close
                ) + "?"
            else:
                listed = ", ".join(candidates)
                if len(candidates) > _MAX_SUGGESTIONS:
                    listed += f", ... ({len(candidates)} total)"
                message += f". Registered VMs: {listed}."
            # Both branches above end in sentence-final punctuation, so this reads
            # correctly either way.
            message += " Use a uuid to refer to one unambiguously."
        super().__init__(message)


class AmbiguousName(RosterError):
    """A name matches more than one registered VM.

    Carries the candidates, each with the alias that matched it. The reason
    matters: asked for `ubuntu`, the caller is confused why `provider:
    PROVISIONING` is in the list, and the answer is that its `.vmx` is called
    `ubuntu-22.04-amd64.vmx`. A list of bare names gives the caller no way to
    work that out, so they either pick wrongly or give up.
    """

    def __init__(self, name: str, matches: Sequence[tuple[str, str]]) -> None:
        self.name = name
        # Kept as plain names for callers that just want the list; the reason is
        # available separately and is what the message renders.
        self.candidates = [vm_name for vm_name, _ in matches]
        self.matches = list(matches)

        if all(reason == "its display name" for _, reason in matches):
            detail = ""
        else:
            rendered = "; ".join(
                f"{vm_name} (matched {reason})" for vm_name, reason in matches
            )
            detail = f": {rendered}"

        super().__init__(
            f"display name {name!r} matches {len(matches)} VMs{detail}. "
            "Identify the VM by uuid instead."
        )


class IdentifierMismatch(RosterError):
    """uuid and name were both given and they point at different VMs.

    Silently preferring one would discard half the caller's intent. For a
    function whose job is to be the trust boundary before any mutating tool, a
    caller who names one VM by uuid and a different one by name has made a
    mistake worth surfacing rather than resolving.
    """


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

    @property
    def vmx_stem(self) -> str:
        """The `.vmx` filename without its extension, e.g. `WindowsServer2019`.

        Usually a different label from the display name, and often the one the
        user recognizes: the display name is set by whatever created the VM,
        while the filename is what shows up in Explorer.
        """
        return Path(self.vmx).stem

    @property
    def aliases(self) -> tuple[str, ...]:
        """Every spelling this VM answers to, most authoritative first.

        Includes the prefix-stripped name so `GOAD-DC01` resolves the VM the
        registry calls `provider: GOAD-DC01`, and the `.vmx` stem so
        `WindowsServer2019` resolves too. Comparison against these is
        case-insensitive; the registry's own casing is what gets reported back.
        """
        candidates = [self.name]

        stripped = _PREFIX_RE.sub("", self.name).strip()
        if stripped and stripped != self.name:
            candidates.append(stripped)

        stem = self.vmx_stem.strip()
        if stem:
            candidates.append(stem)

        seen: list[str] = []
        for value in candidates:
            if value and value.casefold() not in {v.casefold() for v in seen}:
                seen.append(value)
        return tuple(seen)


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

    Can be overridden via VMWARE_INVENTORY_PATH environment variable.
    """
    env_path = os.environ.get("VMWARE_INVENTORY_PATH")
    if env_path:
        return Path(os.path.expandvars(env_path))
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


def registry(path: Path | None = None) -> RosterSnapshot:
    """Read the registry. Called on every tool invocation, never cached.

    Caching was tried and removed. The file is ~7 KB and parses in well under a
    millisecond, so the cache saved nothing measurable while creating a failure
    mode that is genuinely hard to diagnose: register a new VM, `list_vms`
    shows it, and `vm_status` on that same VM fails, because the two tools were
    reading different snapshots. Order-dependent behaviour nobody can see is
    worse than a redundant read, and there was no refresh tool to paper over
    it.

    `main()` still reads at startup, so a broken registry is reported when the
    server boots instead of on the first tool call.
    """
    return load_roster(path)


def resolve(
    identifier: str | None = None,
    *,
    uuid: str | None = None,
    name: str | None = None,
) -> RegisteredVm:
    """Map a caller-supplied identifier to exactly one registered VM.

    Names are matched loosely on purpose. A caller who writes "GOAD-DC01" has
    named the VM correctly even though the registry calls it "provider:
    GOAD-DC01", and refusing correct input because of a prefix is the kind of
    failure that makes a tool unusable. A UUID is matched exactly and only
    after normalizing case and separators.

    Args:
        identifier: Either a UUID or a name, matched as whichever it looks
            like.
        uuid: Explicit UUID form. Takes precedence over `name`, but if `name`
            also matches a *different* VM that is an error rather than a
            silent choice.
        name: Explicit name form. A UUID passed here is still recognized as a
            UUID, because a caller who pastes a uuid into the wrong argument
            should get the right VM, not a confusing "no such name".

    Returns:
        The single matching RegisteredVm.

    Raises:
        UnknownVm: Nothing matched, or the registry is unusable.
        AmbiguousName: A name matched more than one VM.
        IdentifierMismatch: uuid and name were both given and disagree.
    """
    snapshot = registry()
    if not snapshot.ok:
        raise RosterError(snapshot.error or "registry unavailable")

    explicit_uuid = uuid
    explicit_name = name
    bare = identifier if explicit_uuid is None and explicit_name is None else None

    # Classify each supplied value by shape rather than by which argument it
    # arrived in, so a uuid pasted into `name` still resolves as a uuid.
    uuid_query = explicit_uuid or (bare if _is_uuid_shaped(bare or "") else None)
    name_query = explicit_name or bare
    if name_query and _is_uuid_shaped(name_query):
        uuid_query = uuid_query or name_query
        name_query = None

    by_uuid = _find_by_uuid(snapshot, uuid_query) if uuid_query else None
    by_name = _find_by_name(snapshot, name_query) if name_query else None

    # Both supplied and pointing at different VMs is a caller mistake worth
    # surfacing. Quietly preferring the uuid would discard the name entirely,
    # and this function is the trust boundary every mutating tool will sit
    # behind.
    if by_uuid and by_name and by_uuid.uuid != by_name.uuid:
        raise IdentifierMismatch(
            f"uuid {uuid_query!r} is {by_uuid.name!r} but name "
            f"{name_query!r} is {by_name.name!r}. Supply one identifier, not "
            "two that disagree."
        )

    if by_uuid:
        return by_uuid
    if by_name:
        return by_name

    # Nothing matched. Tailor the message to what was actually supplied.
    # A uuid that matched nothing is a truncated paste or a typo, and the useful
    # fact is its length -- listing every registered VM would be noise, and
    # telling the caller to "use a uuid" when they just did is worse.
    names = [vm.name for vm in snapshot.vms]

    if uuid_query and not name_query:
        raise UnknownVm(
            f"uuid {uuid_query!r}", names, as_uuid=True, uuid_text=uuid_query
        )

    if uuid_query and name_query:
        raise UnknownVm(
            f"uuid {uuid_query!r} or name {name_query!r}",
            names,
            name_text=name_query,
        )

    if name_query:
        raise UnknownVm(f"name {name_query!r}", names, name_text=name_query)

    raise UnknownVm("an empty identifier", names)


def _find_by_uuid(
    snapshot: RosterSnapshot, query: str
) -> RegisteredVm | None:
    """Exact uuid match, or None. Never falls back to name matching.

    A mistyped UUID reports an error rather than quietly resolving some other
    VM, which for a future power-off tool would be catastrophic.
    """
    target = normalize_uuid(query)
    for vm in snapshot.vms:
        if vm.normalized_uuid == target:
            return vm
    return None


def _matching_alias(vm: RegisteredVm, needle: str) -> tuple[str, str] | None:
    """If `needle` matches one of `vm`'s aliases, return (alias, human reason).

    The reason is what makes an ambiguity message debuggable instead of just
    noisy: it distinguishes "its display name is this" from "its `.vmx` file is
    called that", which are entirely different things to have collided.
    """
    folded = needle.casefold()
    for alias in vm.aliases:
        if alias.casefold() != folded:
            continue
        if alias == vm.name:
            return alias, "its display name"
        if alias == vm.vmx_stem:
            return alias, f"its .vmx filename {alias!r}"
        # The only remaining alias shape is the prefix-stripped name.
        return alias, f"its display name without the {_PREFIX_RE.match(vm.name).group(0).strip()!r} prefix"
    return None


def _find_by_name(
    snapshot: RosterSnapshot, query: str
) -> RegisteredVm | None:
    """Match a name across the registry's spelling variants.

    Three tiers, each strictly looser than the last, stopping at the first that
    matches anything:

    1. The registry's exact display name.
    2. Any accepted alias, case-insensitively. This is what makes "GOAD-DC01"
       resolve "provider: GOAD-DC01" and "WindowsServer2019" resolve a VM
       named something else entirely.
    3. A unique substring. "DC01" and "wazuh" work. Guarded by a minimum length
       so "01" does not match most of the lab, and by requiring uniqueness so
       "goad" does not silently pick one of seven.

    Raises:
        AmbiguousName: More than one VM matched, carrying the alias each matched
            on so the caller can see why.
    """
    needle = query.strip()
    if not needle:
        return None

    # Collect every tier-1 hit before returning any of them. Returning on the
    # first would make two VMs sharing a display name resolve to whichever came
    # first in the file, which is exactly the silent wrong answer this is
    # supposed to prevent.
    exact = [vm for vm in snapshot.vms if vm.name == needle]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise AmbiguousName(needle, [(vm.name, "its display name") for vm in exact])

    folded = needle.casefold()

    aliased: list[tuple[RegisteredVm, str, str]] = []
    for vm in snapshot.vms:
        hit = _matching_alias(vm, needle)
        if hit:
            aliased.append((vm, hit[0], hit[1]))
    if len(aliased) == 1:
        return aliased[0][0]
    if len(aliased) > 1:
        raise AmbiguousName(needle, [(vm.name, why) for vm, _, why in aliased])

    if len(folded) < _MIN_SUBSTRING:
        return None

    partial: list[tuple[RegisteredVm, str, str]] = []
    for vm in snapshot.vms:
        for alias in vm.aliases:
            if folded in alias.casefold():
                partial.append((vm, alias, f"a substring of {alias!r}"))
                break
    if len(partial) == 1:
        return partial[0][0]
    if len(partial) > 1:
        raise AmbiguousName(needle, [(vm.name, why) for vm, _, why in partial])

    return None
