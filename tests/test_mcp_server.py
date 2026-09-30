"""M0 foundation tests: prove the MCP server starts, is reachable, and answers.

What this actually does: each test spawns `python src/vm_mcp/test_server.py` as
a real background subprocess and speaks the MCP protocol to it over that
process's stdin/stdout pipes. Nothing is mocked. There is no VMware
instrument involved and no VM is touched.

Run:

    .venv\\Scripts\\python.exe -m pytest -v

Written against mcp==2.2.0 (pinned). Three v2 API facts are baked in here and
each one cost a debugging cycle to find, so they are worth stating:

  * `Client.send_ping()` does not work. The wire-level `ping` method was
    removed in the 2026-07-28 spec; it raises MCPError("Method not found")
    unless the client is put in mode='legacy'. Liveness is proven by calling
    a real tool instead.
  * Fields are snake_case: `Tool.input_schema`, not `inputSchema`;
    `CallToolResult.is_error`, not `isError`.
  * Tool failures do NOT raise. `Client` defaults to `raise_exceptions=False`,
    so an unknown tool or a bad argument comes back as a CallToolResult with
    `is_error=True`. Assert on the flag, not on an exception.

Scope note: the protocol tests below drive the stdio transport, because a
subprocess is self-contained and leaves nothing behind. The HTTP transport is
covered separately by research/tmp/http_client_check.py, which connects to an
already-running server. That split is deliberate -- an HTTP test would need to
bind a port, and a port left bound by a crashed test run is a nuisance that
teaches people to distrust the suite.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Awaitable, Callable

import pytest
from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "src" / "vm_mcp" / "test_server.py"

# OpenCode budgets 5000 ms by default for the tools/list handshake. This is a
# generous ceiling for a regression guard, not the real budget -- the point is
# to catch a future change that starts doing I/O at import time.
MAX_HANDSHAKE_SECONDS = 5.0


def server_params() -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER)],
        cwd=str(ROOT),
    )


def with_client(body: Callable[[Client], Awaitable[Any]]) -> Any:
    """Spawn the server, run `body` against a live client, tear it down."""

    async def runner() -> Any:
        async with Client(server_params()) as client:
            return await body(client)

    return asyncio.run(runner())


def test_server_file_exists() -> None:
    assert SERVER.is_file(), f"server entrypoint missing: {SERVER}"


def test_handshake_completes_and_reports_identity() -> None:
    """The core M0 gate: the server starts and completes an MCP handshake."""

    async def body(client: Client) -> tuple:
        info = client.server_info
        assert info is not None, "server did not report serverInfo"
        return info, client.protocol_version

    import time

    t0 = time.perf_counter()
    info, protocol = with_client(body)
    elapsed = time.perf_counter() - t0

    assert info.name == "vmware"
    assert protocol == "2026-07-28", f"unexpected protocol revision: {protocol}"
    assert elapsed < MAX_HANDSHAKE_SECONDS, (
        f"handshake took {elapsed:.2f}s, over the {MAX_HANDSHAKE_SECONDS}s "
        "ceiling -- something is doing I/O before mcp.run()"
    )


def test_tools_are_advertised_with_schemas_and_annotations() -> None:
    async def body(client: Client) -> dict[str, Any]:
        result = await client.list_tools()
        return {t.name: t for t in result.tools}

    tools = with_client(body)

    assert set(tools) == {"ping", "add"}, f"unexpected tool set: {sorted(tools)}"

    for name, tool in tools.items():
        assert tool.description, f"{name} has no description; the model gets nothing"
        assert tool.input_schema is not None
        assert tool.annotations is not None, f"{name} is missing tool annotations"
        assert tool.annotations.read_only_hint is True, f"{name} should be read-only"

    # Schema is derived from the type hints, not hand-written. If this breaks,
    # the arguments are no longer being communicated to the model.
    add_props = tools["add"].input_schema["properties"]
    assert add_props["a"]["type"] == "integer"
    assert add_props["b"]["type"] == "integer"
    assert set(tools["add"].input_schema["required"]) == {"a", "b"}

    assert tools["ping"].input_schema["properties"] == {}


def test_ping_tool_round_trips() -> None:
    async def body(client: Client) -> Any:
        return await client.call_tool("ping")

    result = with_client(body)

    assert result.is_error is False
    assert result.structured_content is not None
    assert result.structured_content["pong"] is True
    assert result.structured_content["server"] == "vmware"
    assert result.structured_content["timestamp"]


def test_add_tool_round_trips_typed_arguments() -> None:
    """Proves typed arguments and structured return values survive the round trip."""

    async def body(client: Client) -> list[Any]:
        return [
            await client.call_tool("add", {"a": 2, "b": 3}),
            await client.call_tool("add", {"a": -10, "b": 10}),
        ]

    results = with_client(body)

    assert results[0].is_error is False
    assert results[0].structured_content == {"result": 5}
    assert results[1].structured_content == {"result": 0}


def test_unknown_tool_reports_error_instead_of_raising() -> None:
    async def body(client: Client) -> Any:
        return await client.call_tool("does_not_exist")

    result = with_client(body)

    assert result.is_error is True
    assert "does_not_exist" in result.content[0].text


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param({"a": 1, "b": "not-a-number"}, id="wrong-type"),
        pytest.param({"a": 1}, id="missing-arg"),
        pytest.param({}, id="no-args"),
    ],
)
def test_bad_arguments_are_rejected(arguments: dict[str, Any]) -> None:
    """A bad call must fail loudly. Silence here would mean the model gets
    a confident-looking wrong answer instead of an error."""

    async def body(client: Client) -> Any:
        return await client.call_tool("add", arguments)

    result = with_client(body)

    assert result.is_error is True
    assert result.content[0].text


# --- transport selection -------------------------------------------------
#
# Pure unit tests on argument parsing and the startup banner. They are here
# because the default transport is the difference between "opencode spawns a
# process" and "opencode connects to a service someone else started", and
# because HTTP currently ships with no authentication at all. Both of those
# should be hard to change by accident.


def test_default_transport_is_stdio() -> None:
    """stdio must stay the default: it is the mode that opens no port.

    A default flip to http would mean that merely starting the server starts
    a listener, which is the opposite of the safe default.
    """
    from vm_mcp import test_server

    assert test_server.parse_args([]).transport == "stdio"


def test_http_defaults_come_from_module_constants() -> None:
    """A listener on 0.0.0.0 would be reachable by anything that can route to
    this machine, and this server can power off a domain controller. Loopback
    has to be the default so widening the bind is a deliberate flag."""
    from vm_mcp import test_server

    args = test_server.parse_args(["--transport", "http"])

    assert args.host == test_server.DEFAULT_HTTP_HOST == "127.0.0.1"
    assert args.port == test_server.DEFAULT_HTTP_PORT
    assert args.path == test_server.DEFAULT_HTTP_PATH
    assert isinstance(args.port, int)


def test_http_settings_are_ignored_while_on_stdio() -> None:
    """--port with no --transport must not imply HTTP. The transport is chosen
    explicitly, so a stray flag from a copy-pasted command line cannot quietly
    start a listener."""
    from vm_mcp import test_server

    args = test_server.parse_args(["--port", "9999"])

    assert args.transport == "stdio"
    assert args.port == 9999


def test_environment_does_not_configure_the_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Configuration comes from this file, not the environment.

    An environment variable is invisible configuration: it gets set in a shell
    profile, outlives the reason it was set, and the server then listens
    somewhere the source does not mention. The regression this guards is the
    exact one that motivated dropping the env layer.
    """
    from vm_mcp import test_server

    monkeypatch.setenv("VM_MCP_TRANSPORT", "http")
    monkeypatch.setenv("VM_MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("VM_MCP_PORT", "1234")
    monkeypatch.setenv("VM_MCP_PATH", "/somewhere/else")

    args = test_server.parse_args([])

    assert args.transport == "stdio"
    assert args.host == "127.0.0.1"
    assert args.port == test_server.DEFAULT_HTTP_PORT
    assert args.path == test_server.DEFAULT_HTTP_PATH


def test_http_banner_reports_the_settings_it_will_use() -> None:
    """The startup message is the only place the effective settings are
    visible, so it has to state the real values rather than a generic string."""
    from vm_mcp import test_server

    banner = test_server.http_banner("127.0.0.1", 8765, "/mcp")

    assert "127.0.0.1" in banner
    assert "8765" in banner
    assert "/mcp" in banner
    assert "http://127.0.0.1:8765/mcp" in banner


def test_http_banner_warns_that_the_endpoint_is_unauthenticated() -> None:
    """No token, no TLS, no client identity check. The tool surface is about to
    include power-off, so this has to be said at the moment it becomes true."""
    from vm_mcp import test_server

    banner = test_server.http_banner("127.0.0.1", 8765, "/mcp")

    assert "no authentication" in banner.lower()
    assert "power off" in banner.lower()


def test_http_banner_escalates_the_warning_off_loopback() -> None:
    """On 0.0.0.0 the endpoint is not merely local, and the banner must not
    describe it as though it were."""
    from vm_mcp import test_server

    banner = test_server.http_banner("0.0.0.0", 8765, "/mcp")

    assert "reachable by anything that can route" in banner
    assert "only processes on this machine" not in banner
