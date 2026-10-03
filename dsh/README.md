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

On a host with no browser — DSH in a container or on a server, say — use the device flow instead:
it opens no listener and needs no redirect, so nothing outside the process is involved in the
login. You approve a short code on any device that already has a session with the authorization
server.

```bash
node bin/mcp-oauth-gateway.mjs login --device --url https://your-mcp-host/mcp --client-id <id>
```

`print-config` prints the exact block below, already filled in with your port and token.

## 2. Install this bundle

**DSH has no browsable plugin marketplace.** Its Plugins panel installs from a **package name**
(npm), a **Git repository URL**, a **tarball**, or a **local path**; it also lists the official
plugins that ship with DSH and the bundles already installed. So there is nothing to "find" —
you install from one of those sources.

This repository *is* the bundle: its `package.json` declares `dsh.bundle.patch`, pointing at
[`dsh/cordis.patch.yml`](cordis.patch.yml). Install it any of these ways:

| Source | What to give the Plugins panel |
|---|---|
| Local path | the **repository root** (the directory containing `package.json`) |
| Git repository | `https://github.com/zmhhaha/mcp-oauth-gateway` |
| Package name | `mcp-oauth-gateway` (published on npm) |

The installation dialog also lets you choose the npm registry (official npm, the mainland-China
mirror, or a custom address); that only matters for the package-name route.

If you would rather not install a bundle at all, paste the contents of `dsh/cordis.patch.yml`
into your profile's `cordis.patch.yml` by hand — same effect.

Then replace the two placeholders:

| Placeholder | Replace with |
|---|---|
| `serverName: CHANGE_ME` | any name matching `[A-Za-z0-9_-]{1,32}`; tools appear as `mcp__<serverName>__<tool>` |
| `x-mcp-gateway-token: CHANGE_ME` | the token printed by `serve` / `print-config` |

The token is the gateway's own stable secret. It is deliberately **not** the OAuth token, so
this file never changes when the OAuth token rotates. (It has to be pasted rather than derived:
the MCP client's `headers` are static config, and the loader evaluates `!!js` expressions once
at load, so there is no hook that could read it at request time.)

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
  fail with a connection error. Keep it running rather than starting it on demand: the refresh
  token rotates only while the gateway runs, and a refresh token has its own lifetime on the
  authorization server — if the gateway stays down past it, you have to `login` again.
- **A restart of the MCP server invalidates the MCP session.** The gateway forwards that
  faithfully: the server answers `404` (per the MCP spec) and DSH's client does **not**
  re-`initialize` on its own. Recover by starting a new conversation, toggling the row, or
  restarting DSH.
- **Loopback only.** The gateway binds `127.0.0.1` and `::1` and refuses callers without its
  token, but any process running as your user can read the state file and use that token. That
  is the same trust boundary as DSH's own local UI.
