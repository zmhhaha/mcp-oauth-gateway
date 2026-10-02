# DSH bundle: connect DSH to an MCP server that requires OAuth

DSH's MCP client (`@deepseek-ai/dsh-mcp-client`) sends a **static** `Authorization` header and
implements **no** OAuth: there is no discovery, no handling of a `401` challenge, and no way to
recompute headers per request (`headers` is handed straight to
`StreamableHTTPClientTransport`'s `requestInit`, and loader `!!js` expressions are evaluated
once at load).

So a server that follows the MCP authorization flow is unreachable from DSH — unless something
else holds the credential. That is what [`mcp-oauth-gateway`](../README.md) is for.

```
dsh-mcp-client ──(static, stable header)──▶ 127.0.0.1:33419/mcp ──(OAuth Bearer, auto-refreshed)──▶ your MCP server
```

## 1. Run the gateway and log in

```bash
node bin/mcp-oauth-gateway.mjs login --url https://your-mcp-host/mcp
node bin/mcp-oauth-gateway.mjs serve --url https://your-mcp-host/mcp --port 33419
```

`print-config` prints the exact block below, already filled in with your port and token.

## 2. Install this bundle

In the DSH Web UI, open the **Plugins** panel in the sidebar and install this directory as a
local bundle (`dsh/`), or paste its `cordis.patch.yml` contents into your profile's
`cordis.patch.yml`.

Then replace the two placeholders:

| Placeholder | Replace with |
|---|---|
| `serverName: CHANGE_ME` | any name matching `[A-Za-z0-9_-]{1,32}`; tools appear as `mcp__<serverName>__<tool>` |
| `x-mcp-gateway-token: CHANGE_ME` | the token printed by `serve` / `print-config` |

The token is the gateway's own stable secret. It is deliberately **not** the OAuth token, so
this file never changes when the OAuth token rotates.

## 3. Verify

Ask the agent in a **new conversation** to call a tool from the new server (for example
`mcp__openspec__list_projects`). Success means DSH reached the gateway and the gateway reached
the MCP server with a valid OAuth token.

## Multiple MCP servers

One gateway process serves one upstream URL. For several servers, either run one gateway per
server on a different port, or point the row at a gateway whose port matches that server's.
Each row needs its own `serverName`.

## Caveats

- **The gateway must be running.** DSH starts no process for it; run it however you keep local
  services alive (a startup shortcut, a service manager, a terminal). If it is down, the tools
  fail with a connection error.
- **A restart of the MCP server invalidates the MCP session.** The gateway forwards that
  faithfully: the server answers `404` (per the MCP spec) and DSH's client does **not**
  re-`initialize` on its own. Recover by starting a new conversation, toggling the row, or
  restarting DSH.
- **Loopback only.** The gateway binds `127.0.0.1` and `::1` and refuses callers without its
  token, but any process running as your user can read the state file and use that token. That
  is the same trust boundary as DSH's own local UI.
