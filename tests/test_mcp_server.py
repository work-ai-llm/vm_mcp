"""M0 foundation tests: prove the MCP server starts, is reachable, and answers.

What this actually does: each test spawns `python src/vm_mcp/server.py` as a
real background subprocess and speaks the MCP protocol to it over that
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
