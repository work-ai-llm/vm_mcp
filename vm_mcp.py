"""Launcher so `python vm_mcp.py --transport http` works from a checkout.

What this buys: a fresh worktree is runnable the moment `git worktree add`
returns, with no install step. `python -m vm_mcp` needs the checkout's src on
sys.path, which in practice means an editable install -- and an editable install
points at exactly one checkout, so a second worktree either needs its own venv or
inherits the first one's source by accident. Putting src on the path here makes
each worktree self-contained and lets one venv be shared deliberately.

The `sys.path` insert is load-bearing, not tidiness. This file is named
`vm_mcp.py` and the package is named `vm_mcp`, and running a script puts the
script's directory on sys.path. Left alone, `import vm_mcp` resolves to *this
file* instead of the package, and the failure reads like a circular import but is
not one. `src/vm_mcp/server.py` and `src/vm_mcp/__main__.py` both document that
trap from the inside; this is the one place it is handled rather than avoided.

Launch with any of:

    python vm_mcp.py               # this file
    python -m vm_mcp               # shortest, but needs the install
    vm-mcp                         # console script, from the venv
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from vm_mcp.server import main  # noqa: E402  (must follow the sys.path insert)

if __name__ == "__main__":
    main()