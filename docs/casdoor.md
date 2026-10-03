# Field notes: Casdoor as the authorization server for MCP

These are the things that actually cost time when wiring an MCP server to Casdoor. They were
established on Casdoor **4.11.0**; later versions may differ. Nothing here is required for
`mcp-oauth-gateway` to work — it is context for whoever debugs the next integration.

## 1. Casdoor advertises dynamic client registration even when it is disabled

`/.well-known/oauth-authorization-server` includes:

```json
{ "registration_endpoint": "https://<casdoor>/api/oauth/register" }
```

A spec-following client therefore tries RFC 7591 first and gets:

```json
{"error":"invalid_client_metadata",
 "error_description":"dynamic client registration is disabled for this organization"}
```

The switch is `organization.dcr_policy` (`varchar(100)`). Casdoor's own check is
(`object/oauth_dcr.go`):

```go
if org.DcrPolicy == "" || org.DcrPolicy == "disabled" { /* reject */ }
```

so **any non-empty value other than `disabled` enables it**. On 4.11.0 there is **no UI control**
for it — set it through the API/DB, and remember Casdoor caches applications and organizations in
memory (see §5).

### Enabling DCR is not automatically the right answer

Every registration mints a **new application with a random `client_id`**, and Casdoor sets the
token's `aud` to that `client_id` (see §2 for when it does not). A resource server that pins a
single audience in a static allow-list therefore cannot accept DCR-issued tokens — you have to
switch to a `resource`-based audience (which is the RFC 8707 thing the MCP spec asks for anyway).
Also consider that DCR opens client registration to anyone who can reach the authorization
server.

## 2. `aud` is the `resource` when the client sends one

With RFC 8707 support (Casdoor `v4.11.0`, from PR casdoor/casdoor#5098, merged 2026-02-15),
`object/token_jwt.go` does:

```go
claims.Audience = []string{application.ClientId + "-org-" + user.Owner}
// RFC 8707: Use resource as audience when provided
if resource != "" { claims.Audience = []string{resource} }
```

Consequences worth internalising:

- A **plain** authorization-code flow (no `resource`) produces `aud = <client_id>`.
- A flow with `resource=https://host/mcp` produces `aud = https://host/mcp`.
- MCP clients are **supposed** to send `resource` (the MCP spec requires it), and at least one
  real client does even when you hand it a pre-configured `client_id`.
- Therefore a resource server that accepts only `<client_id>` will **reject** a correct client
  with `unexpected "aud" claim value` — while the client looks perfectly authenticated in the
  browser.

The robust configuration is to accept **both**:

```
OIDC_AUDIENCE = "<client_id>,<resource-url>"
```

## 3. Dynamic registration and refresh

- Casdoor's DCR creates applications in the target organization; there is no scoping, so the
  switch is all-or-nothing per organization.
- Refresh: as long as the application's `grant_types` include `refresh_token`, silent renewal
  works. Whether the refreshed token keeps the RFC 8707 `resource` audience has been fixed in
  several follow-ups (casdoor/casdoor#5294, #5666, #5689, #5690, #5744) — if your build predates
  them, accept both audiences as in §2 rather than relying on the refresh preserving
  `resource`.

## 4. Redirect URIs

Casdoor matches the registered `redirect_uris` entries and accepts wildcards such as
`http://localhost:*`. Registering **both** `http://localhost:*` and `http://127.0.0.1:*` is
recommended: clients disagree about which form they send (Claude Code v2.1.229 sent
`http://127.0.0.1:PORT/callback` and servers that exact-match the other form rejected the
sign-in; v2.1.231 switched back).

Note that Casdoor's **authorization endpoint does not validate `redirect_uri`** — it renders the
login page for any value, including unregistered ones and relative URIs. Validation happens when
the code is issued. Do not conclude "the redirect URI is fine" from a successful authorize
request.

## 5. Casdoor caches configuration in memory

`application` (and `organization`) objects are cached. Consequences:

- Editing the database directly **does not take effect until Casdoor restarts**.
- Any later save of that object from the admin UI can write the cached (stale) copy **back over**
  your database edit.
- Prefer the admin UI/API, which updates the cache itself.

A related trap: a `UPDATE ...` that is never committed looks exactly like a change that was
reverted. Verify with a fresh connection:

```sql
SELECT json_length(redirect_uris), redirect_uris
  FROM casdoor.application WHERE name = '<application>';
```

## 6. Trailing-dot/OIDC discovery

Casdoor serves both `/.well-known/oauth-authorization-server` and
`/.well-known/openid-configuration`. Use the discovery documents rather than hard-coding
endpoints — `jwks_uri` in particular is `/.well-known/jwks` with **no** `.json` suffix, which is
an easy thing to get wrong by pattern-matching.

## 7. Enabling the device flow

Two separate checks gate RFC 8628, and both live on the **application**:

| Check | Enforced at | Symptom when it is off |
|---|---|---|
| the app's `signinMethods` contains `Device login` | `controllers/auth.go`, `HasSigninMethod("Device login")` | `POST /api/device-auth` answers `unauthorized_client`: *device login is not enabled for this application* |
| the app's `grantTypes` contains `urn:ietf:params:oauth:grant-type:device_code` | `object/token_oauth.go`, `IsGrantTypeValid` | the device code is issued, then the token exchange is refused |

In 4.11.0 the **new console can set only the second one**. The application's *OIDC/OAuth* tab has a
grant-types picker that lists `Device Code`, but the *Signin methods* editor was not carried over
from the old console: `web-old/src/ApplicationEditPage.js` still renders it, while the new per-tab
components under `web/src/components/application/` contain no `signinMethod` reference at all, and
the built bundle carries no such label. Saving from the new UI **preserves** an existing
`Device login` entry — the whitelist in `web/src/pages/ApplicationEditPage.tsx` includes that name
— it just cannot add one.

So set `signinMethods` through the database or the admin API; `POST /api/update-application` with an
admin token refreshes the in-memory cache, while a direct SQL edit does not (§5). The entry itself:

```json
{ "name": "Device login", "displayName": "Device login", "rule": "All" }
```

`HasSigninMethod` matches `name` exactly and ignores hidden rows, so the name must be
`Device login` verbatim. Afterwards, `POST {issuer}/api/device-auth` with the client id should
return `device_code`/`user_code` instead of the error above.
