# Threat model

Scope: static review of an MCP server manifest and its launch config, before a client connects.

## Assets

1. Files and credentials on the client host.
2. The model context (prompt, history, prior tool output).
3. The user's authority: what the client can do on the user's behalf.

## Trust boundaries

1. Client to server process: the client launches the server with `command`, `args` and `env`.
2. Server to client: tool names, descriptions and schemas enter the model context as text.
3. Tool output to context: results re-enter the model as text. This boundary is not scanned.

## Threats and rules

| Threat | Boundary | Rule |
|---|---|---|
| Server or tool runs arbitrary commands on the host | 1 | MCP001 |
| Server reads or writes outside the intended directory | 1 | MCP002 |
| Secret stored in config or visible in process args | 1 | MCP003 |
| Description steers the model (tool poisoning) | 2 | MCP004 |
| Second server redefines a trusted tool name (shadowing) | 2 | MCP005 |
| Loose schema lets the model pass unvetted fields to a risky tool | 2 | MCP006 |
| Package changes under the client after review (supply chain) | 1 | MCP007 |

## What the scanner cannot see

1. Runtime behaviour: what the server does after launch.
2. Tool output: injection that arrives in a result, not a description (boundary 3).
3. Manifest drift: a description edited after approval. Re-scan on every change.
4. Paraphrased or encoded instructions that match no pattern.
5. Package contents behind a pinned version.
6. Authorisation inside the server. A clean manifest is not a safe server.

## Operator steps

1. Run `python3 mcp_scan.py <manifests>` before each new server is enabled.
2. Block the server on exit 1 or exit 2.
3. Review MEDIUM findings by hand.
4. Re-run after any server update.
