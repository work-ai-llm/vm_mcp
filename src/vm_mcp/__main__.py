"""Makes `python -m vm_mcp` work.

Without this, running the package needs `-m vm_mcp.server`. This exists so the
launch command is the shortest one that works, and so there is no module in
here whose name shadows the package it belongs to -- a module named
`vm_mcp.py` inside a package named `vm_mcp` makes `from vm_mcp import roster`
resolve to the file itself when you run it from inside this directory, which
fails with an import error that reads like a circular import and is not one.
The root `vm_mcp.py` does carry that name; it puts `src` ahead of itself to
compensate, and is the launcher to use from a worktree.
"""

from vm_mcp.server import main

if __name__ == "__main__":
    main()