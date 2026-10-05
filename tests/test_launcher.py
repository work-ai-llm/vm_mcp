"""Tests for the root `vm_mcp.py` launcher.

What this actually does: runs the launcher as a real subprocess and checks which
copy of the package it picks up. The failure mode being guarded against is
silent, not loud -- a launcher with the wrong `sys.path` still starts, it just
runs the code from the wrong checkout -- so these tests assert on the *resolved
source path*, not only on the exit code.

Why the resolved path is the thing worth asserting
---------------------------------------------------
Worktrees are the reason this file exists. A checkout with no editable install
has no `src` on `sys.path` at all, and an editable install in a shared venv
points at exactly one checkout, so anything launched the ordinary way runs that
one checkout's code no matter which directory the shell is sitting in. If the
launcher did not put its own `src` first, work two and work three would silently
test work one.

What is covered:

  * The real launcher resolves its own `src` -- proven with `--help`, which
    exits 0 from argparse before any VMware code runs.
  * The precedence is real rather than incidental: a temp checkout containing
    the launcher and a sentinel package wins over the installed package.
  * It does not depend on the current directory.
  * It exposes the same CLI surface as `python -m vm_mcp`, so it cannot drift.

Run:

    .venv\\Scripts\\python.exe -m pytest -v
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SHIM = REPO_ROOT / "vm_mcp.py"

# Prints the `src` directory that won the import. Imports only: calling main()
# would start a server and block the test run.
_PROBE = """\
import os
import sys

{insert}
import vm_mcp

print(os.path.dirname(os.path.dirname(os.path.abspath(vm_mcp.__file__))))
"""

_INSERT = (
    "sys.path.insert(0, "
    "os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))"
)


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )


def _make_sentinel_checkout(root: Path) -> Path:
    """Build a checkout whose package prints a marker instead of serving.

    Mirrors the real layout: launcher at the root, package under `src`. The
    marker goes to stdout because a real `main()` would talk to VMware, and this
    test is about path resolution, not about serving.
    """
    pkg = root / "src" / "vm_mcp"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "server.py").write_text(
        "import os\n"
        "\n"
        "\n"
        "def main():\n"
        "    print('SENTINEL-REACHED')\n"
        "    print(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))\n",
        encoding="utf-8",
    )
    (root / "vm_mcp.py").write_text(SHIM.read_text(encoding="utf-8"), encoding="utf-8")
    return root


def test_launcher_help_exits_zero() -> None:
    """`python vm_mcp.py --help` starts, which is the shadowing regression guard.

    Without the `sys.path` insert this fails with an ImportError that reads like
    a circular import but is not one -- the launcher shadows the package it is
    trying to import.
    """
    result = _run([str(SHIM), "--help"], cwd=REPO_ROOT)

    assert result.returncode == 0, result.stderr
    assert "--transport" in result.stdout


def test_launcher_works_from_any_cwd() -> None:
    """Absolute-path launch must not depend on the shell's directory.

    This is the whole difference from `python -m vm_mcp`, which resolves relative
    to cwd and so only works from the checkout root.
    """
    result = _run([str(SHIM), "--help"], cwd=REPO_ROOT.parent)

    assert result.returncode == 0, result.stderr
    assert "--transport" in result.stdout


def test_launcher_prefers_its_own_src_over_installed_package(tmp_path: Path) -> None:
    """A sibling `src` outranks the shared venv's editable install."""
    checkout = _make_sentinel_checkout(tmp_path / "worktree-b")

    result = _run([str(checkout / "vm_mcp.py")], cwd=checkout)

    assert "SENTINEL-REACHED" in result.stdout, (
        f"launcher did not use its own src; stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    assert str(checkout / "src") in result.stdout


def test_probe_with_insert_resolves_sibling_src(tmp_path: Path) -> None:
    """The insert is what produces the precedence in the test above."""
    checkout = _make_sentinel_checkout(tmp_path / "worktree-c")
    probe = checkout / "probe.py"
    probe.write_text(_PROBE.format(insert=_INSERT), encoding="utf-8")

    result = _run([str(probe)], cwd=checkout)

    assert result.returncode == 0, result.stderr
    assert str(checkout / "src") in result.stdout


def _installed_src(cwd: Path) -> Path:
    """Ask the interpreter where its editable install points.

    Two things are deliberately not assumed:

    * That it is `REPO_ROOT / "src"`. In a worktree those differ: the venv's
      `__editable__*.pth` names whichever checkout was installed, which is not
      necessarily the one running this test.
    * That the current directory is safe to run from. Passing a directory that
      contains this repository's `vm_mcp.py` makes a bare `import vm_mcp` resolve
      to the launcher instead of the package and fail with
      `ModuleNotFoundError: 'vm_mcp' is not a package`. That is the shadowing
      trap this launcher exists to handle, and it is re-entered here by asking
      the interpreter a question with an implicit `sys.path[0]`.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os, vm_mcp; "
            "print(os.path.dirname(os.path.dirname(os.path.abspath(vm_mcp.__file__))))",
        ],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert result.returncode == 0, (
        f"could not read the installed package from {cwd}: {result.stderr}"
    )
    return Path(result.stdout.strip())


def test_control_probe_without_insert_resolves_installed_package(tmp_path: Path) -> None:
    """Control: without the insert, the installed package wins.

    Exists so the precedence test cannot pass vacuously. If this probe ever
    started resolving to a temp checkout, the assertions above would no longer
    be measuring anything. It also documents the trap: same directory, same
    interpreter, one line of difference.
    """
    probe = tmp_path / "probe.py"
    probe.write_text(_PROBE.format(insert=""), encoding="utf-8")

    result = _run([str(probe)], cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    resolved = Path(result.stdout.strip())
    expected = _installed_src(tmp_path)
    assert resolved.resolve() == expected.resolve(), (
        f"control probe expected the installed package at {expected}, "
        f"got {resolved}"
    )


def test_launcher_matches_package_entrypoint() -> None:
    """The launcher and `python -m vm_mcp` must expose the same CLI surface.

    Guards against the launcher drifting: if a flag is added to `parse_args` and
    the launcher ever stopped delegating to `main()`, this is what notices.
    """
    via_shim = _run([str(SHIM), "--help"], cwd=REPO_ROOT)
    via_module = _run(["-m", "vm_mcp", "--help"], cwd=REPO_ROOT)

    assert via_shim.returncode == via_module.returncode == 0, via_module.stderr
    assert via_shim.stdout == via_module.stdout


@pytest.mark.parametrize("flag", ["--transport", "--host", "--port", "--path"])
def test_launcher_exposes_every_flag(flag: str) -> None:
    assert flag in _run([str(SHIM), "--help"], cwd=REPO_ROOT).stdout