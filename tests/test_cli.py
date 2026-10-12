"""Tests for the Ctrl+C path through `server.main`.

Pressing Ctrl+C runs a full, successful shutdown and *then* surfaces as a
KeyboardInterrupt: uvicorn captures SIGINT to stop gracefully and re-raises it
afterwards, and anyio re-raises it again. Left uncaught, the interpreter prints a
CancelledError traceback, then "During handling of the above exception, another
exception occurred", then KeyboardInterrupt, and exits with the Ctrl+C status
code -- a wall of text that reads like a crash even though the shutdown
succeeded. `main` catches exactly that interrupt and reports it in one line.

What is covered:

  * HTTP and stdio both turn an interrupt into a clean return, no traceback.
  * The message goes to stderr, where the banner and logs already go.
  * Only KeyboardInterrupt is caught. A real fault still propagates, so this
    cannot hide a genuine failure behind a friendly message.

These call `main` with `mcp.run` and the port check replaced, so no server
starts and no port is bound.

Run:

    ..\\.venv\\Scripts\\python.exe -m pytest tests/test_cli.py -v
"""

from __future__ import annotations

from typing import Any

import pytest

from vm_mcp import server


def _interrupting_run(*args: Any, **kwargs: Any) -> None:
    """Stand in for `mcp.run`, which raises KeyboardInterrupt on Ctrl+C."""
    raise KeyboardInterrupt


def test_http_ctrl_c_returns_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(server, "_port_is_free", lambda host, port: True)
    monkeypatch.setattr(server.mcp, "run", _interrupting_run)

    server.main(["--transport", "http", "--port", "8767"])

    err = capsys.readouterr().err
    assert "shut down cleanly" in err


def test_stdio_ctrl_c_returns_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(server.mcp, "run", _interrupting_run)

    server.main(["--transport", "stdio"])

    assert "shut down cleanly" in capsys.readouterr().err


def test_a_real_failure_is_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The interrupt handler must not become a blanket `except`."""

    def explode(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("not an interrupt")

    monkeypatch.setattr(server, "_port_is_free", lambda host, port: True)
    monkeypatch.setattr(server.mcp, "run", explode)

    with pytest.raises(RuntimeError, match="not an interrupt"):
        server.main(["--transport", "http", "--port", "8767"])


def test_the_interrupt_message_is_a_single_clean_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No traceback, no "During handling" block -- just the one line."""
    monkeypatch.setattr(server.mcp, "run", _interrupting_run)

    server.main(["--transport", "stdio"])

    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "KeyboardInterrupt" not in err
    assert "During handling" not in err
    assert server._INTERRUPTED in err
