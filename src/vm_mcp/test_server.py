"""vm_mcp — an MCP server for the local VMware Workstation GOAD lab.

MILESTONE 0 (foundation). This file exists to prove the plumbing works
end to end, not to be the product. The tools below are deliberately trivial
and touch no VMware instrument whatsoever. The real tools land in M1 onward.

Two hard constraints from the research phase are encoded here from the start,
because they are cheap now and expensive to retrofit:

1. stdio transport only. stdout belongs to JSON-RPC framing, so every
   diagnostic in this file goes to stderr. A stray print() corrupts the
   protocol stream and the client sees a dead server.
2. Nothing blocking before mcp.run(). OpenCode budgets 5000 ms by default
   for the tool-fetch handshake. This module does zero I/O at import and
   zero I/O in main() before run() so a cold filesystem cache cannot push
   startup past that budget.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

__version__ = "0.0.0"

mcp = MCPServer(
    name="vmware",
    version=__version__,
    instructions=(
        "Controls and inspects a local VMware Workstation lab of Windows "
        "domain controllers and servers. Status: M0 foundation, the real "
        "tools are not built yet."
    ),
)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False)


@mcp.tool(annotations=READ_ONLY)
def ping() -> dict[str, Any]:
    """Check that the MCP server is alive and responding.

    Takes no arguments. Returns the server's own clock, which is useful for
    telling a hung server apart from a slow one.
    """
    return {
        "pong": True,
        "server": mcp.name,
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool(annotations=READ_ONLY)
def add(a: int, b: int) -> int:
    """Add two integers and return the sum.

    Exists to prove that typed arguments and return values survive the round
    trip. It will be removed once a real tool covers the same ground.

    Args:
        a: First addend.
        b: Second addend.
    """
    return a + b


def main() -> None:
    # stderr, never stdout. See the module docstring.
    print(f"vm_mcp {__version__} starting on stdio", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
