// Token persistence, one state file per MCP endpoint.
//
// The gateway holds the credential so no client's config file has to. State lives outside
// the repo, in the OS config directory, and the file is chmod 0600 where the platform
// supports it (on Windows the ACL of the user's own profile directory is the boundary).

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** Refresh this long before the token actually expires, to absorb clock skew. */
export const EXPIRY_SKEW_MS = 60_000;

export function defaultStoreDir(env = process.env) {
  if (env.MCP_OAUTH_GATEWAY_STORE) return env.MCP_OAUTH_GATEWAY_STORE;
  if (process.platform === 'win32') {
    return path.join(env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'mcp-oauth-gateway');
  }
  return path.join(env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'mcp-oauth-gateway');
}

/** Deterministic file per target, so several MCP servers can share one store directory. */
export function storeFileFor(mcpUrl, dir = defaultStoreDir()) {
  const key = crypto.createHash('sha256').update(String(mcpUrl)).digest('hex').slice(0, 16);
  return path.join(dir, `${key}.json`);
}

export function loadState(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw new Error(`cannot read state file ${file}: ${error.message}`, { cause: error });
  }
}

export function saveState(file, state) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(tmp, file);
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // Windows: no POSIX modes. The profile directory is the boundary.
  }
  return file;
}

/**
 * The secret local callers must present. It is deliberately *not* the OAuth token: it is
 * stable, so a client's config can carry it once, while the OAuth token rotates freely.
 */
export function ensureLocalToken(state) {
  if (!state.localToken) state.localToken = crypto.randomBytes(24).toString('base64url');
  return state.localToken;
}

/**
 * A name a client can use for this MCP server, derived from its host:
 * `openspec.panghuer.top` → `openspec`. DSH constrains server names to
 * `[A-Za-z0-9_-]{1,32}`, hence the sanitising and truncation.
 */
export function serverNameFor(mcpUrl) {
  let label = '';
  try {
    label = new URL(mcpUrl).hostname.split('.')[0];
  } catch {
    label = '';
  }
  return label.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32) || 'mcp';
}

function expiresAtFrom(response, now) {  const seconds = Number(response?.expires_in);
  return Number.isFinite(seconds) && seconds > 0 ? now + seconds * 1000 : null;
}

/** Merge a token/refresh response into state, preserving a refresh token the server omits. */
export function applyTokenResponse(state, response, now = Date.now()) {
  const previous = state.tokens || {};
  state.tokens = {
    access_token: response.access_token,
    token_type: response.token_type || previous.token_type || 'Bearer',
    scope: response.scope || previous.scope,
    refresh_token: response.refresh_token || previous.refresh_token,
    expires_at: expiresAtFrom(response, now) ?? previous.expires_at ?? null,
    obtained_at: now,
  };
  return state;
}

/**
 * What can be done with the stored credential right now.
 * @returns {'missing'|'expired'|'refreshable'|'fresh'}
 */
export function tokenStatus(state, { now = Date.now(), skewMs = EXPIRY_SKEW_MS } = {}) {
  const tokens = state?.tokens;
  if (!tokens?.access_token) return 'missing';
  if (tokens.expires_at == null) return 'fresh'; // No declared lifetime: let the server decide.
  if (tokens.expires_at - skewMs > now) return 'fresh';
  return tokens.refresh_token ? 'refreshable' : 'expired';
}

/** A description safe to print: never includes a token, refresh token or client secret. */
export function describeState(state, { now = Date.now(), skewMs = EXPIRY_SKEW_MS } = {}) {
  const status = tokenStatus(state, { now, skewMs });
  return {
    mcpUrl: state.mcpUrl,
    resource: state.resource,
    authorizationServer: state.authorizationServer,
    clientId: state.clientId,
    clientSecretPresent: Boolean(state.clientSecret),
    tokenAuthMethod: state.clientSecret ? state.tokenAuthMethod || null : null,
    dynamicallyRegistered: Boolean(state.dynamicallyRegistered),
    status,
    expiresAt: state.tokens?.expires_at ? new Date(state.tokens.expires_at).toISOString() : null,
    refreshTokenPresent: Boolean(state.tokens?.refresh_token),
    scopes: state.tokens?.scope || null,
    // Names only: a value could be sensitive, and the names are what diagnose a misconfiguration.
    authorizeParams: Object.keys(state.authorizeParams || {}),
    tokenParams: Object.keys(state.tokenParams || {}),
  };
}
