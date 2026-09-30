"""vm_mcp — an MCP server for the local VMware Workstation GOAD lab.

MILESTONE 0 (foundation). This file exists to prove the plumbing works
end to end, not to be the product. The tools below are deliberately trivial
and touch no VMware instrument whatsoever. The real tools land in M1 onward.

Two hard constraints from the research phase are encoded here from the start,
because they are cheap now and expensive to retrofit:

1. Diagnostics go to stderr, never stdout. On stdio, stdout is the JSON-RPC
    channel and a stray print() corrupts the framing, so the client just sees
    a dead server with no diagnostic anywhere useful.
2. Nothing blocking before the transport starts. OpenCode budgets 5000 ms by
    default for the tool-fetch handshake. This module does zero I/O at import
    and zero I/O before run() so a cold filesystem cache cannot push startup
    past that budget.

Two transports, one tool surface
--------------------------------
`--transport stdio` (the default) speaks JSON-RPC over stdin/stdout. There the
MCP client *launches* this process and owns its lifetime. That is what the
test suite exercises, and it is the safe default: no port, nothing reachable.

`--transport http` runs this as a standalone service that something else
connects to. The client is handed a URL and never spawns a process, so the
server's lifetime is independent of any client's. That is the mode used when
opencode is pointed at an already-running server.

Both transports carry an identical tool surface, and nothing in a tool
definition knows or cares which one delivered the call.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

__version__ = "0.0.0"

# HTTP settings live here as plain module constants, read by the CLI defaults
# and printed at startup. Deliberately not read from the environment: an
# environment variable is invisible configuration. It gets set in some shell
# profile or launcher, outlives the reason it was set, and the server then
# listens somewhere the config file does not mention. One place to look, and
# one place to change.
#
# Loopback is the default because binding 0.0.0.0 would expose a server that
# can power off a domain controller to anything that can route to this
# machine. Widening the bind has to be a deliberate flag, not an inherited
# environment variable.
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8765
DEFAULT_HTTP_PATH = "/mcp"

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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the command line. Defaults come from the module constants above.

    stdio is the default transport and is meant to stay that way: it opens no
    port, so a server that can power off a domain controller is not sitting on
    a socket waiting for anything.
    """
    parser = argparse.ArgumentParser(
        prog="vm-mcp",
        description="MCP server for a local VMware Workstation GOAD lab.",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="stdio: the client launches this process. http: serve and wait "
        "to be connected to. Default: stdio.",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HTTP_HOST,
        help=f"HTTP bind address. Default: {DEFAULT_HTTP_HOST} (loopback only).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_HTTP_PORT,
        help=f"HTTP port. Default: {DEFAULT_HTTP_PORT}.",
    )
    parser.add_argument(
        "--path",
        default=DEFAULT_HTTP_PATH,
        help=f"HTTP endpoint path. Default: {DEFAULT_HTTP_PATH}.",
    )
    return parser.parse_args(argv)


def http_banner(host: str, port: int, path: str) -> str:
    """The startup message for HTTP mode: settings, URL, and a security warning.

    Printed on every HTTP start, including a routine loopback one. There is no
    authentication on this transport yet, so anyone who can reach the socket
    can call every tool on it -- and the tool surface is going to include
    power-off. That is worth saying out loud at the moment it becomes true,
    rather than in a document nobody reads before widening the bind.
    """
    if host in ("127.0.0.1", "localhost", "::1"):
        exposure = (
            "bound to loopback, so only processes on this machine can reach it"
        )
    else:
        exposure = (
            f"bound to {host}, which is reachable by anything that can route "
            f"to this machine"
        )

    return "\n".join(
        [
            f"vm_mcp {__version__} — HTTP transport",
            "",
            f"  host      : {host}",
            f"  port      : {port}",
            f"  path      : {path}",
            f"  url       : http://{host}:{port}{path}",
            "",
            "  SECURITY: no authentication is established on this endpoint. "
            "There is no",
            "  token, no TLS and no client identity check, so anything that can "
            "reach the",
            "  socket can call every tool this server exposes. Right now the "
            "tools are",
            "  harmless placeholders; once the mutating tools land, this "
            "endpoint will be",
            "  able to power off a domain controller and anyone who can reach "
            f"it can",
            f"  ask for that. Currently {exposure}.",
            "",
        ]
    )


def _port_is_free(host: str, port: int) -> bool:
    """True if nothing is already listening on host:port.

    A second server on the same port does not fail loudly; the OS hands the
    socket to the first process and the second one dies with a bind error that
    scrolls past in a launcher window. Checking up front lets the failure
    explain itself.
    """
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError:
            return False
    return True


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    if args.transport == "http":
        if not _port_is_free(args.host, args.port):
            print(
                f"vm_mcp {__version__}: {args.host}:{args.port} is already in "
                f"use. A server may already be running here -- if so, that is "
                f"fine, just connect to it. Otherwise pass --port to pick "
                f"another.",
                file=sys.stderr,
                flush=True,
            )
            raise SystemExit(1)

        # stderr, never stdout. See the module docstring.
        print(http_banner(args.host, args.port, args.path), file=sys.stderr, flush=True)
        mcp.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            streamable_http_path=args.path,
        )
        return

    print(f"vm_mcp {__version__} starting on stdio", file=sys.stderr, flush=True)
    mcp.run()


if __name__ == "__main__":
    main()
