# mcp-oauth-gateway

**OAuth 2.1 for MCP clients that only know how to send a static `Authorization` header.**

Many MCP clients can't authenticate against an MCP server that implements the spec's
authorization flow. They send one fixed header, never discover the authorization server, and
don't react to a `401` challenge — so the server is simply unreachable:

```
Error POSTing to endpoint: {"error":{"code":-32001,"message":"Bearer token required"}}
Server status: needs-auth
SDK auth failed: Dynamic Client Registration rejected (HTTP 400):
  {"error":"invalid_client_metadata","error_description":"dynamic client registration is disabled..."}
```

Hand-pasting a long-lived JWT into the client's config "works", and then goes stale: the token
expires, ends up in plaintext in several config files, and every client needs its own copy.

This gateway sits on loopback and holds the credential *for* the client:

```
        static header                    OAuth 2.1, refreshed automatically
client ───────────────▶ 127.0.0.1:33419/mcp ─────────────────────▶ your MCP server
                              │
                              └── performs RFC 9728 discovery, PKCE, and silent refresh;
                                  keeps tokens in the OS config dir (0600), not in your config
```

The client keeps talking to a loopback URL with a **stable local token that is not the OAuth
credential**, so nothing in the client's config ever changes when the OAuth token rotates.

Zero dependencies. Node ≥ 20 only (it uses the built-in `fetch`, `node:http` and `node:test`).

## What it does on the wire

1. `POST <mcp-url>` → reads the `401` and its `WWW-Authenticate` challenge.
2. Fetches the **Protected Resource Metadata** (RFC 9728) the challenge points at.
3. Fetches the authorization server's metadata (RFC 8414, falling back to
   `openid-configuration`).
4. Registers a client dynamically (RFC 7591) **if the server allows it**; otherwise it tells you
   exactly what to configure instead.
5. Opens the browser for an **authorization code + PKCE (S256)** flow, with
   `resource=<mcp-url>` (RFC 8707) so the token's audience is bound to your server.
6. Stores the access and refresh token, and renews silently before expiry.

Nothing is vendor-specific: any MCP server that publishes protected-resource metadata and any
OAuth 2.1 authorization server with PKCE works.

## Quick start

No clone needed — it is published on npm:

```bash
# 1. Authorize once (opens a browser; stores tokens outside any repo)
npx mcp-oauth-gateway login --url https://your-mcp-host/mcp

# 2. Run the gateway
npx mcp-oauth-gateway serve --url https://your-mcp-host/mcp --port 33419

# 3. Print ready-to-paste client configuration
npx mcp-oauth-gateway print-config --url https://your-mcp-host/mcp
```

Or from a checkout (`git clone https://github.com/zmhhaha/mcp-oauth-gateway`), replacing
`npx mcp-oauth-gateway` with `node bin/mcp-oauth-gateway.mjs`.

If your authorization server does not offer dynamic client registration, add `--client-id <id>`
to `login`. The error message tells you the redirect URI to register.

### Headless hosts: containers, CI, servers

The flow above opens a browser and receives the redirect on `http://localhost:<port>/oauth/callback`,
which cannot work on a host with no browser. Use the **RFC 8628 device flow** instead — no browser,
no listener, no port forwarding, nothing outside the process is needed to complete it:

```bash
npx mcp-oauth-gateway login --device --url https://your-mcp-host/mcp --client-id <id>
```

It prints a short code and a URL. Open that URL on **any** device where you are already signed in
to the authorization server — a phone is fine — and enter the code. The command polls until you
approve, then stores exactly what the browser flow would have stored (refresh token included), so
later restarts renew silently.

The authorization server must advertise `device_authorization_endpoint` and must have the device
flow enabled for your client. For Casdoor that means the application needs **both** the `Device
Code` grant type and a `Device login` signin method; 4.11.0's UI can set only the first, so see
[Casdoor notes](docs/casdoor.md#7-enabling-the-device-flow).

## Pointing a client at it

### DSH (DeepSeek Harness)

DSH's MCP client has no OAuth at all, so this is the intended use case.

This repository **is** the DSH bundle — its `package.json` declares `dsh.bundle.patch` — so the
Plugins panel can install it straight from this repository's URL or from a local checkout.
(DSH has no browsable marketplace: it installs from a package name on npm, a Git repository URL,
a tarball, or a local path, and otherwise only lists DSH's own official plugins. This package is
published on npm, so the package-name route works too.)

See [`dsh/README.md`](dsh/README.md) for the two values `print-config` gives you, and the caveats.

### Any client that accepts custom headers

```json
{
  "mcpServers": {
    "your-server": {
      "type": "http",
      "url": "http://127.0.0.1:33419/mcp",
      "headers": { "x-mcp-gateway-token": "<from print-config>" }
    }
  }
}
```

### Good old curl

```bash
curl -sS -X POST http://127.0.0.1:33419/mcp \
  -H "x-mcp-gateway-token: <from print-config>" \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
```

Clients that **do** implement OAuth (Claude Code, Codex with its experimental Rust client)
should keep using their own flow — this gateway is for the ones that can't.

## Commands

| Command | What it does |
|---|---|
| `login --url <mcp-url>` | Interactive authorization; stores access + refresh token |
| `serve --url <mcp-url>` | Runs the loopback gateway until interrupted |
| `status --url <mcp-url>` | Shows the stored credential — never the tokens themselves |
| `refresh --url <mcp-url>` | Forces a refresh now (handy from a scheduled task) |
| `print-config --url <mcp-url>` | Prints client configuration for DSH, JSON clients and curl |
| `logout --url <mcp-url>` | Deletes the stored credential |

| Option | Meaning |
|---|---|
| `--client-id <id>` | Skip dynamic registration and use this client id |
| `--port <n>` | Loopback port (default `33419`) |
| `--redirect-host <h>` | Host inside the redirect URI (default `localhost`) |
| `--scope <list>` | Space/comma separated scopes (default `openid,email,profile`) |
| `--auth-server <url>` | Issuer override for servers without an RFC 9728 challenge |
| `--store <dir>` | State directory (default: the OS config dir) |
| `--no-open` | Don't try to open a browser; print the URL instead |

## Security and limitations

- **Loopback only.** It binds `127.0.0.1` and `::1` (both, because `localhost` resolves to
  either — a mismatch here breaks the browser redirect). It refuses any request without its
  token.
- **The local token is not the OAuth credential.** It is stable and can live in client config
  files; the OAuth tokens stay in the gateway's state file (mode `0600` under the OS config dir,
  never in a client's config).
- **Same-user processes can read that state file.** The gateway's token is readable by anything
  running as you — the same trust boundary as any local dev tool. Do not run it on a shared
  machine as a shared user.
- **One upstream per process**, one login at a time, in-memory state. Run several gateways (one
  port each) for several MCP servers.
- **Keep it running.** Tokens refresh only while the gateway runs. A refresh token has its own
  lifetime on the authorization server, so a gateway that stays down past it needs a fresh
  `login` — starting it on demand works, but leaving it running is what makes the setup
  hands-off.
- **No retry on a mid-flight `401`.** Expiry is handled proactively (including reading `exp` from
  the JWT when the server omits `expires_in`); a token that the server rejects anyway means
  re-login.
- **`chmod 0600` is POSIX-only.** On Windows the ACL of your own profile directory is the
  boundary.
- The gateway does not verify tokens or signatures — that is the MCP server's job. It only
  obtains and forwards them.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `dynamic client registration rejected` | The authorization server has DCR disabled (many do) | Register an application manually and pass `--client-id` |
| `... does not advertise a registration_endpoint` | Same, and there is nothing to register against | Same |
| `401 ... unexpected "aud" claim value` from the MCP server, right after a successful login | The token's audience is the `resource` while the server only allows the `client_id` (or vice versa) | Accept both in the server's audience allow-list |
| Login page loads, then "redirect URI mismatch" | The redirect URI is not registered | Register `http://<redirect-host>:<port>/oauth/callback` — or `http://localhost:*` if your server supports wildcards |
| The authorization server says something like **"Failed to sign in"** | The URL was opened in a context that has no session there — an embedded preview/popup window, or a different browser. (Some clients open links in a webview, which also cannot finish a provider sign-in.) | Open it in the browser where you are signed in. `login` already opens your default browser, so prefer letting it do that. If the gateway still completed the flow, it succeeded — check `status` rather than the window you were looking at |
| Browser says success, client still unauthenticated | The client got a token but it is not bound to this server (RFC 8707 `resource`) | Same as the `aud` row |
| Works, then stops after some days | The refresh token was revoked, or the server rotated it before Casdoor supported that | Re-run `login` |
| `Protocol "https:" not supported` | Would be a bug in this gateway | Please report it |

## Development

```bash
node --test          # 32 tests, no network required
```

The suite covers the RFC 7636 PKCE vector, challenge and metadata parsing, the manual-client
error paths, token-store semantics, the loopback proxy (including a test that proves SSE frames
are **streamed and not buffered**), and the transport selection per upstream scheme.

### Releasing

Two traps that cost real time on the first publish, both silent:

1. **Never write a `bin` path with a leading `./`.** `"mcp-oauth-gateway": "./bin/x.mjs"` makes
   npm consider the entry invalid and **drop the whole `bin` field** from the published
   package — `npm publish` only warns, and `npx` then fails with no obvious cause. Use
   `"bin/x.mjs"`. `npm pkg fix` corrects it.
2. **npm 11 has staged publishing, and a bypass-2FA token is no longer the recommended route.**
   `npm publish` may leave the version unpublished while the registry reserves the name with a
   `0.0.0-stage` placeholder; the metadata for a brand-new package also takes a minute to appear,
   so an immediate `npm view` or `npx <pkg>@<version>` can report `ETARGET` even though the
   publish succeeded. Check the version endpoint (`registry.npmjs.org/<pkg>/<version>`) before
   concluding anything, and prefer `npm stage publish` + `npm stage approve` over a bypass token
   (npm's own guidance). `npm stage list` reads `GET /-/stage`.

## Notes on specific authorization servers

- [Casdoor](docs/casdoor.md) — DCR behaviour, `aud = resource`, redirect matching, and the
  configuration cache that quietly reverts database edits.

## License

MIT
