# Security posture

## HTTP transport currently has no authentication

No token, no TLS, no client identity check. Anything that can reach the socket
can call every tool the server exposes. The server says so on startup, in the
banner, on every HTTP launch — because the tool surface is about to include
power-off, and "I bound it to loopback" is a mitigation, not a control.
Authentication has to be settled before the bind is widened off this machine.

## What the real controls are

Tool annotations are hints to the model about what a call does. They are **not**
access control: nothing enforces them, they carry no authorisation, and a caller
that ignores them gets the same response. The real controls are structural:

1. **The closed roster.** Exactly one function (`roster.resolve`) turns a caller
   identifier into a `.vmx` path, and it only ever returns a path the VMware
   registry itself lists. No caller-supplied path ever reaches `vmrun`, so a
   "resolve this path and power it on" primitive does not exist. See
   [`architecture.md`](architecture.md).
2. **The no-shell subprocess layer.** `vmrun` is invoked as an argument vector
   through `create_subprocess_exec`, never through a shell, so a VM named
   `a & b` is one argument and not a command. See
   [`architecture.md`](architecture.md).
3. **Client-side gating of the mutating tools.** The mutating tools (shipped
   in M2) are disabled by default in client configuration, gated behind an
   explicit per-agent opt-in -- the `tools` block, not the server, is where
   that switch lives:

   ```jsonc
   "tools": {
     "vmware_list_vms": true,
     "vmware_vm_status": true,
     "vmware_host_resources": true,

     "vmware_start_vm": false,
     "vmware_stop_vm": false,
     "vmware_restart_vm": false
   }
   ```

   Enabling one is a deliberate edit to that file. The gate ships *with* the
   tools it guards (M2), not one milestone after them -- see
   [#15](https://github.com/work-ai-llm/vm_mcp/issues/15) for the argument
   that made it non-deferable. Note the registry cannot distinguish a lab
   member from an appliance: it lists `wazuh-4.7.5`, an 8 GB SIEM host, so an
   operator flipping a switch should know which of the 8 registered VMs they
   are handing to an agent.

## Remote access

The plan is to reach the server from a second machine over Tailscale. That is a
bind-address change (`--host 0.0.0.0`) plus an authentication story, not a
redesign — which is the main reason the HTTP transport exists alongside stdio.
Guest credentials, when they are needed, are environment variables and never
belong in a committed config.
