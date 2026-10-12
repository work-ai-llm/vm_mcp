# Usage

## How the client finds the server

The server is registered in **`opencode.jsonc` at the repository root** —
project-local, version-controlled, and travelling with the code. It is *not*
written into the user's global config at `C:\Users\Zver\.config\opencode\`.

There are two ways to run it, and the choice determines how the client behaves.

## Remote (what the committed config uses)

Start the server yourself; opencode only connects.

```powershell
# Terminal 1 — the server, running independently
..\.venv\Scripts\vm-mcp.exe --transport http

# equivalently, without relying on the console script being installed:
..\.venv\Scripts\python.exe -m vm_mcp --transport http

# or, needing neither the console script nor the editable install:
python vm_mcp.py --transport http

# Terminal 2 — opencode, from this directory
opencode
```

Stop the server with Ctrl+C. It shuts down gracefully and prints one line,
`vm_mcp: interrupted -- shut down cleanly`, rather than the CancelledError
traceback that a graceful uvicorn shutdown otherwise leaves behind.

The venv lives at `..\.venv`, one level above the repository, so that it is the
project's single shared environment rather than an asset of the main checkout.
Activate it with `..\.venv\Scripts\Activate.ps1`.

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "vmware": {
      "type": "remote",
      "url": "http://127.0.0.1:8765/mcp",
      "enabled": true,
      "timeout": 15000
    }
  }
}
```

There is no `command` and no `cwd` here, because opencode is not running
anything. It holds a URL. Consequences worth being explicit about: the server
outlives any client, several clients can share one server, and a crash in
opencode cannot take the lab tools down. The flip side is that the server must
be started separately — with nothing running on the port, opencode reports
`✗ failed` and offers no tools.

## Launching from a worktree

`vm_mcp.py` at the repository root is a launcher, and it is the one to use when
working in a [git worktree](https://git-scm.com/docs/git-worktree). The other two
forms resolve the package through the venv's `__editable__*.pth`, which names
exactly one checkout — so in a second worktree they would quietly run the *first*
worktree's code.

`vm_mcp.py` puts its own `src` ahead of that, so each worktree runs its own code,
and the one shared `.venv` is enough for all of them:

```powershell
git worktree add ..\feature-x -b feature-x
..\.venv\Scripts\python.exe ..\feature-x\vm_mcp.py --transport http
```

No `pip install -e .` per worktree. `research\` and `PLAN.md` live one level above
the repository, outside Git, and are reached from any worktree as `..\research\`
and `..\PLAN.md`.

### One consequence of the launcher's name

`vm_mcp.py` sits beside the package it imports, so it shadows it for anything
that has the repository root on `sys.path` and does a bare `import vm_mcp`. From
the repository root:

```powershell
python -m vm_mcp --help            # fine -- runpy executes the launcher
python -c "import vm_mcp"          # ModuleNotFoundError: 'vm_mcp' is not a package
python vm_mcp.py --help            # fine -- the launcher inserts src ahead of itself
pytest                             # fine -- pyproject sets pythonpath = ["src"]
```

`python -c "import vm_mcp"` is the only casualty, and it is a diagnostic one-liner
rather than a launch path. `import vm_mcp` from any other directory is unaffected.

## Local stdio (spawned by the client)

```jsonc
{
  "mcp": {
    "vmware": {
      "type": "local",
      "command": [
        "D:\\llms\\models\\testing\\vm_mcp\\.venv\\Scripts\\vm-mcp.exe"
      ],
      "cwd": "D:\\llms\\models\\testing\\vm_mcp\\vm_mcp",
      "enabled": true,
      "timeout": 15000
    }
  }
}
```

`command` is an argument array, not a shell string: element 0 is the executable,
the rest are its arguments. `cwd` is the working directory the process is started
in, which is what relative paths inside the server resolve against. The absolute
interpreter path is deliberate, so nothing depends on `PATH` resolution finding
the right Python.

## How the model learns what to call

Worth being clear about, because the config does not say it. The config only says
**where the server is**. The tool surface is discovered at runtime: opencode
performs the MCP handshake, the server answers `tools/list` with a name, a
description and a JSON Schema per tool, and opencode puts those into the model's
context as callable functions. The model picks from what was advertised; it is
not guessing and nothing is hardcoded client-side. The SDK derives the schema
from the Python signature and the docstring, which is why the docstrings on
`list_vms` and `vm_status` are written as tool documentation rather than as code
comments.

## Transports and settings

`--transport stdio` (the default), `--host`, `--port`, `--path`. Defaults come
from module constants at the top of `src/vm_mcp/server.py` — `DEFAULT_HTTP_HOST`,
`DEFAULT_HTTP_PORT`, `DEFAULT_HTTP_PATH` — and are printed on every HTTP start:

```
--transport stdio   (default)   client launches the process; no port is opened
--host    127.0.0.1             loopback: only this machine can reach it
--port    8765
--path    /mcp                  arbitrary; the client is handed the URL
```

The endpoint path is not fixed by the protocol. `/mcp` is the SDK's convention,
not a requirement — `--path /vm_run_mcp` works identically, because the client is
simply given that URL. Distinct paths are how you would route several servers
behind one reverse proxy later.

**There is no environment-variable configuration.** Settings live in the source
file on purpose. An environment variable is invisible configuration: it gets set
in a shell profile, outlives the reason it was set, and the server then listens
somewhere the source does not mention. A regression test pins that behaviour, so
`VM_MCP_*` in the environment cannot change how the server starts.
