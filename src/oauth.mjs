// The client half of the MCP authorization flow, in one dependency-free file.
//
// Why this exists: plenty of MCP clients can only send a *static* `Authorization` header,
// so an MCP server that implements the spec's authorization flow (RFC 9728 discovery +
// OAuth 2.1 + PKCE) is simply unreachable from them. This module implements the flow so a
// local gateway can hold the credential instead of the client's config file.
//
// Spec references:
//   RFC 9728  Protected Resource Metadata (how the client finds the authorization server)
//   RFC 8414  Authorization Server Metadata
//   RFC 7636  PKCE
//   RFC 8707  Resource Indicators (binds the token's `aud` to this MCP server)
//   RFC 7591  Dynamic Client Registration (optional; many servers disable it)
//
// Nothing here is Casdoor- or vendor-specific.

import crypto from 'node:crypto';

/** An error with an actionable message: the CLI prints `.message` verbatim. */
export class OAuthError extends Error {
  constructor(message, { code, description, cause } = {}) {
    super(message, { cause });
    this.name = 'OAuthError';
    this.code = code;
    this.description = description;
  }
}

// --------------------------------------------------------------------------- PKCE (RFC 7636)

/** The S256 challenge for a verifier: base64url(SHA-256(ASCII(verifier))). */
export function challengeFor(verifier) {
  return crypto.createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/** A fresh verifier (43 chars of base64url, RFC 7636 §4.1) and its challenge. */
export function createPkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  return { verifier, challenge: challengeFor(verifier) };
}

/** An opaque, unguessable `state` for CSRF protection. */
export function createState() {
  return crypto.randomBytes(16).toString('base64url');
}

// ------------------------------------------------------- RFC 9728 discovery from a 401

/**
 * Pull the `resource_metadata` pointer out of a `WWW-Authenticate` challenge.
 * Tolerates unquoted values and extra parameters, which real servers emit.
 * @returns {string|null} absolute URL, or null when the challenge has no such parameter
 */
export function parseResourceMetadata(challenge) {
  if (!challenge || typeof challenge !== 'string') return null;
  const match = /(?:^|[\s,])resource_metadata\s*=\s*(?:"([^"]+)"|([^\s,]+))/i.exec(challenge);
  const value = match?.[1] ?? match?.[2];
  return value ? value.trim() : null;
}

/**
 * Ordered candidates for an authorization server's metadata document.
 * RFC 8414 §3.1 inserts the well-known segment *before* the issuer's path component;
 * §3 (and every OIDC deployment in the wild) also serves `openid-configuration`.
 */
export function wellKnownCandidates(authorizationServer) {
  const url = new URL(authorizationServer);
  const path = url.pathname.replace(/\/+$/, '');
  const out = [];
  for (const name of ['oauth-authorization-server', 'openid-configuration']) {
    // RFC 8414 §3.1 form: /.well-known/<name><path>
    out.push(new URL(`/.well-known/${name}${path}`, url).toString());
    // Also the plain form, which servers behind a path prefix commonly use.
    if (path) out.push(new URL(`${path}/.well-known/${name}`, url).toString());
  }
  return [...new Set(out)];
}

const MCP_INITIALIZE_BODY = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'mcp-oauth-gateway', version: '0.1.0' },
  },
};

const DEFAULT_TIMEOUT_MS = 15000;

async function getJson(url, { fetchImpl = fetch, timeoutMs = DEFAULT_TIMEOUT_MS, init } = {}) {
  // AbortSignal.timeout() throws on a non-number, and every caller here may omit the option.
  const timeout = Number(timeoutMs) > 0 ? Number(timeoutMs) : DEFAULT_TIMEOUT_MS;
  const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeout) });
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    throw new OAuthError(`${url} did not return JSON (HTTP ${res.status}): ${text.slice(0, 200)}`);
  }
  return { res, body };
}

async function loadAuthorizationServerMetadata(authorizationServer, { fetchImpl, timeoutMs }) {
  const tried = [];
  for (const candidate of wellKnownCandidates(authorizationServer)) {
    tried.push(candidate);
    let body;
    try {
      ({ body } = await getJson(candidate, { fetchImpl, timeoutMs }));
    } catch {
      continue; // A missing metadata document is expected for some candidates; keep looking.
    }
    if (body?.authorization_endpoint && body?.token_endpoint) return body;
  }
  throw new OAuthError(
    `Could not read authorization server metadata for ${authorizationServer}. Tried:\n` +
      tried.map((u) => `  ${u}`).join('\n'),
  );
}

/**
 * Discover who authorizes an MCP endpoint, by triggering its 401 challenge.
 *
 * @param {string} mcpUrl                the MCP endpoint, e.g. https://host/mcp
 * @param {object} [options]
 * @param {string} [options.authorizationServer]  skip PRM discovery and use this issuer
 * @returns {Promise<{resource: string, mcpUrl: string, authorizationServer: string, metadata: object, protectedResourceMetadata: object|null}>}
 */
export async function discoverMcp(mcpUrl, { fetchImpl = fetch, timeoutMs = 15000, authorizationServer } = {}) {
  const url = new URL(mcpUrl);
  let prm = null;
  let resourceMetadataUrl = null;

  if (!authorizationServer) {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify(MCP_INITIALIZE_BODY),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const challenge = res.headers.get('www-authenticate');
    resourceMetadataUrl = parseResourceMetadata(challenge);

    if (!resourceMetadataUrl) {
      throw new OAuthError(
        res.status === 401
          ? `${mcpUrl} answered 401 but its WWW-Authenticate header has no resource_metadata pointer ` +
            `(RFC 9728). Point the gateway at the issuer instead: --authorization-server <issuer-url>.`
          : `${mcpUrl} answered HTTP ${res.status} without a resource_metadata challenge, so there is ` +
            `nothing to authorize. If this server does not implement RFC 9728, pass ` +
            `--authorization-server <issuer-url> and --resource <mcp-url> explicitly.`,
      );
    }

    ({ body: prm } = await getJson(resourceMetadataUrl, { fetchImpl, timeoutMs }));
    if (!prm?.authorization_servers?.length) {
      throw new OAuthError(
        `${resourceMetadataUrl} did not list any authorization_servers, so the issuer cannot be discovered. ` +
          `Pass --authorization-server <issuer-url>.`,
      );
    }
    authorizationServer = prm.authorization_servers[0];
  }

  const metadata = await loadAuthorizationServerMetadata(new URL(authorizationServer).toString(), {
    fetchImpl,
    timeoutMs,
  });

  return {
    mcpUrl,
    resource: prm?.resource || mcpUrl,
    authorizationServer: new URL(authorizationServer).toString(),
    metadata,
    protectedResourceMetadata: prm,
  };
}

// ------------------------------------------------------------------ the authorization flow

/** The three endpoints a flow needs, with a clear error when one is missing. */
export function pickEndpoints(metadata) {
  const { authorization_endpoint: authorizationEndpoint, token_endpoint: tokenEndpoint } = metadata || {};
  if (!authorizationEndpoint || !tokenEndpoint) {
    throw new OAuthError(
      'The authorization server metadata is missing authorization_endpoint and/or token_endpoint.',
    );
  }
  return { authorizationEndpoint, tokenEndpoint, registrationEndpoint: metadata.registration_endpoint };
}

/** RFC 7591 dynamic client registration. Public client: PKCE, no secret. */
export async function registerClient({
  registrationEndpoint,
  redirectUri,
  clientName = 'mcp-oauth-gateway',
  fetchImpl = fetch,
  timeoutMs = 15000,
}) {
  const { res, body } = await getJson(registrationEndpoint, {
    fetchImpl,
    timeoutMs,
    init: {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: clientName,
        redirect_uris: [redirectUri],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      }),
    },
  });
  if (!res.ok || !body?.client_id) {
    const detail = [body?.error, body?.error_description].filter(Boolean).join(': ') || `HTTP ${res.status}`;
    throw new OAuthError(`dynamic client registration rejected (${detail})`, {
      code: body?.error,
      description: body?.error_description,
    });
  }
  return body;
}

/**
 * Decide which client id to use: an explicitly configured one, or a dynamically
 * registered one when the server allows it. The error message matters — this is the
 * step most users get stuck on.
 */
export async function resolveClient({ metadata, clientId, redirectUri, fetchImpl, timeoutMs }) {
  if (clientId) return { clientId, dynamicallyRegistered: false };
  // Read the registration endpoint directly: requiring the other endpoints here would make
  // this helper fail with a confusing message whenever they happen to be absent.
  const registrationEndpoint = metadata?.registration_endpoint;
  if (!registrationEndpoint) {
    throw new OAuthError(
      'This authorization server does not advertise a registration_endpoint, so a client id must be ' +
        `configured:\n  1. register an application with the authorization server\n` +
        `  2. add ${redirectUri} to its allowed redirect URIs\n  3. pass --client-id <client id>`,
    );
  }
  try {
    const registration = await registerClient({ registrationEndpoint, redirectUri, fetchImpl, timeoutMs });
    return { clientId: registration.client_id, dynamicallyRegistered: true, registration };
  } catch (error) {
    throw new OAuthError(
      `${error.message}\n` +
        'Register an application manually instead:\n' +
        `  1. register an application with the authorization server\n` +
        `  2. add ${redirectUri} to its allowed redirect URIs\n` +
        '  3. pass --client-id <client id> (no client secret is needed: this gateway always uses PKCE)',
      { code: error.code, description: error.description },
    );
  }
}

/** Build the URL the user opens in a browser. */
export function buildAuthorizeUrl({
  authorizationEndpoint,
  clientId,
  redirectUri,
  state,
  challenge,
  resource,
  scopes = ['openid', 'email', 'profile'],
}) {
  const url = new URL(authorizationEndpoint);
  // Merge instead of replacing: an authorization endpoint may legitimately carry its own
  // query string (tenant selectors and similar), and `url.search = ...` would drop it.
  const params = {
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes.join(' '),
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    // RFC 8707: ask for a token bound to *this* MCP server. Servers that ignore it are
    // unaffected; servers that honour it (Casdoor >= 4.11 does) emit aud = resource.
    ...(resource ? { resource } : {}),
  };
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return url.toString();
}

async function postForm(tokenEndpoint, params, { fetchImpl, timeoutMs }) {
  const { res, body } = await getJson(tokenEndpoint, {
    fetchImpl,
    timeoutMs,
    init: {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: new URLSearchParams(params).toString(),
    },
  });
  if (!res.ok || body?.error) {
    const detail = [body?.error, body?.error_description].filter(Boolean).join(': ') || `HTTP ${res.status}`;
    throw new OAuthError(`token request failed (${detail})`, { code: body?.error, description: body?.error_description });
  }
  return body;
}

/** Exchange the authorization code. Public client + PKCE, so no client secret. */
export function exchangeCode({ tokenEndpoint, clientId, code, redirectUri, verifier, resource, fetchImpl, timeoutMs }) {
  return postForm(
    tokenEndpoint,
    {
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
      ...(resource ? { resource } : {}),
    },
    { fetchImpl, timeoutMs },
  );
}

/** Silent renewal. `resource` is sent again so the refreshed token stays bound to it. */
export function refreshTokens({ tokenEndpoint, clientId, refreshToken, resource, fetchImpl, timeoutMs }) {
  return postForm(
    tokenEndpoint,
    {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
      ...(resource ? { resource } : {}),
    },
    { fetchImpl, timeoutMs },
  );
}

/**
 * Decode a JWT payload without verifying it. Used only for diagnostics
 * (`status` prints `aud`/`exp`) — never for an authorization decision.
 */
export function decodeJwtPayload(token) {
  try {
    const part = String(token).split('.')[1];
    if (!part) return null;
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}
