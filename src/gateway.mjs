// A loopback gateway in front of an MCP endpoint.
//
//   client (static header, no OAuth)  ->  http://127.0.0.1:PORT/mcp  ->  the real MCP server
//                                                 |
//                                                 +-- holds the OAuth tokens, refreshes them silently,
//                                                     and answers the browser redirect itself.
//
// Two things here are easy to get wrong and are therefore handled explicitly:
//
//  1. **Streaming.** The MCP streamable-HTTP transport uses `text/event-stream`. The proxy
//     pipes the upstream response instead of buffering it, so SSE frames reach the client
//     as they are produced.
//  2. **localhost vs 127.0.0.1.** On Windows `localhost` usually resolves to `::1` first
//     while a naive proxy listens on `127.0.0.1` only, which breaks the OAuth redirect
//     (Claude Code shipped exactly that bug in v2.1.229). We listen on both loopback
//     addresses so a `http://localhost:PORT/...` redirect always lands.

import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { spawn } from 'node:child_process';

import {
  OAuthError,
  buildAuthorizeUrl,
  createPkce,
  createState,
  decodeJwtPayload,
  discoverMcp,
  exchangeCode,
  pickEndpoints,
  refreshTokens,
  resolveClient,
} from './oauth.mjs';
import { applyTokenResponse, describeState, ensureLocalToken, saveState, tokenStatus } from './store.mjs';

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const LOGIN_TIMEOUT_MS = 10 * 60 * 1000;

/** The header a local caller presents, and which must never be forwarded upstream. */
const LOCAL_TOKEN_HEADER = 'x-mcp-gateway-token';

/**
 * node:http refuses to speak `https:` ("Protocol https: not supported"), so the transport
 * has to follow the upstream scheme. Most real MCP endpoints are https, which is exactly
 * why an http-only test server will not catch a mistake here.
 */
export function transportFor(protocol) {
  return protocol === 'https:' ? https : http;
}

/** A promise with its resolve/reject exposed, for "wait until the browser comes back". */
function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  promise.catch(() => {}); // never surface as an unhandled rejection when nobody waits
  return { promise, resolve, reject };
}

/** Compare secrets without leaking length or timing. */
function secretMatches(expected, provided) {
  if (typeof expected !== 'string' || typeof provided !== 'string') return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(provided);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/** The instant the stored access token stops being trustworthy. */
export function effectiveExpiryMs(state) {
  const tokens = state?.tokens;
  if (!tokens?.access_token) return null;
  if (tokens.expires_at != null) return tokens.expires_at;
  const exp = decodeJwtPayload(tokens.access_token)?.exp;
  return typeof exp === 'number' ? exp * 1000 : null;
}

/** Listen on both loopback addresses so `localhost` works whichever way it resolves. */
function listenLoopback(handler, port) {
  const servers = [];
  const errors = [];
  const listen = (host) =>
    new Promise((resolve) => {
      const server = http.createServer(handler);
      server.on('error', (error) => {
        // IPv6 can be unavailable; that is fine as long as one address works.
        errors.push(`${host}: ${error.code || error.message}`);
        resolve(null);
      });
      server.listen(port, host, () => resolve(server));
    });

  return (async () => {
    for (const host of ['127.0.0.1', '::1']) {
      const server = await listen(host);
      if (server) servers.push(server);
    }
    if (!servers.length) throw new Error(`cannot listen on loopback port ${port}: ${errors.join('; ')}`);
    return {
      servers,
      close: () =>
        Promise.all(
          servers.map(
            (server) =>
              new Promise((resolve) => {
                server.close(() => resolve());
                server.closeAllConnections?.();
              }),
          ),
        ),
    };
  })();
}

/**
 * @param {object} options
 * @param {string} options.mcpUrl        the real MCP endpoint (e.g. https://host/mcp)
 * @param {object} options.state         loaded state (see store.mjs); mutated and saved in place
 * @param {string} options.stateFile     where to persist state
 * @param {number} [options.proxyPort]   loopback port the client connects to
 * @param {string} [options.redirectHost='localhost']  host inside the OAuth redirect URI
 * @param {string} [options.redirectPath='/oauth/callback']
 * @param {string} [options.localPath='/mcp']          path the client uses on the proxy
 * @param {boolean} [options.authorizeMissingToken=true]  answer /oauth/login by starting a flow
 */
export async function createGateway(options) {
  const {
    mcpUrl,
    state,
    stateFile,
    proxyPort = 33419,
    redirectHost = 'localhost',
    redirectPath = '/oauth/callback',
    localPath = '/mcp',
    scopes = ['openid', 'email', 'profile'],
    clientId: configuredClientId,
    authorizationServer,
    log = () => {},
    fetchImpl = fetch,
    authorizeMissingToken = true,
  } = options;

  const upstream = new URL(mcpUrl);
  const redirectUri = `http://${redirectHost}:${proxyPort}${redirectPath}`;
  const localToken = ensureLocalToken(state);
  let pending = null; // one login at a time
  let pendingCompletion = null;
  let discovery = null;

  const save = () => saveState(stateFile, state);

  async function discover({ refresh = false } = {}) {
    if (discovery && !refresh) return discovery;
    log(`discovering authorization server for ${mcpUrl} …`);
    discovery = await discoverMcp(mcpUrl, { fetchImpl, authorizationServer });
    state.mcpUrl = mcpUrl;
    state.resource = discovery.resource;
    state.authorizationServer = discovery.authorizationServer;
    save();
    return discovery;
  }

  /** Refresh the access token with the stored refresh token. */
  async function refreshNow() {
    const current = await discover();
    const { tokenEndpoint } = pickEndpoints(current.metadata);
    if (!state.tokens?.refresh_token) throw new OAuthError('no refresh token is stored; run the login flow again');
    log('refreshing access token …');
    const response = await refreshTokens({
      tokenEndpoint,
      clientId: state.clientId,
      refreshToken: state.tokens.refresh_token,
      resource: state.resource,
      fetchImpl,
    });
    applyTokenResponse(state, response);
    save();
    return state.tokens.access_token;
  }

  /** A usable access token, refreshing first when that is possible. */
  async function ensureToken({ now = Date.now() } = {}) {
    const expiry = effectiveExpiryMs(state);
    const fresh = expiry == null ? tokenStatus(state, { now }) === 'fresh' : expiry - 60_000 > now;
    if (fresh && state.tokens?.access_token) return state.tokens.access_token;
    if (state.tokens?.refresh_token) {
      try {
        return await refreshNow();
      } catch (error) {
        log(`refresh failed: ${error.message}`);
      }
    }
    throw new OAuthError(
      'no usable access token is stored for ' + mcpUrl + '. Start a login:\n' +
        `  open http://${redirectHost}:${proxyPort}/oauth/login  (or run the CLI's \`login\`)`,
    );
  }

  /** Build the authorize URL and remember the flow we are waiting for. */
  async function beginLogin() {
    const current = await discover();
    const { authorizationEndpoint } = pickEndpoints(current.metadata);
    const { clientId, dynamicallyRegistered } = await resolveClient({
      metadata: current.metadata,
      clientId: configuredClientId || state.clientId,
      redirectUri,
      fetchImpl,
    });
    state.clientId = clientId;
    state.dynamicallyRegistered = dynamicallyRegistered;
    save();

    const { verifier, challenge } = createPkce();
    const flowState = createState();
    pending = { state: flowState, verifier, startedAt: Date.now() };
    pendingCompletion = deferred();
    const url = buildAuthorizeUrl({
      authorizationEndpoint,
      clientId,
      redirectUri,
      state: flowState,
      challenge,
      resource: current.resource,
      scopes,
    });
    log(`client_id ${clientId}${dynamicallyRegistered ? ' (dynamically registered)' : ''}`);
    return url;
  }

  /** Finish the flow: validate state, exchange the code, persist the tokens. */
  async function finishLogin(params) {
    try {
      const code = params.get('code');
      const returnedState = params.get('state');
      // No pending flow means either a stale/foreign callback, or — the confusing case — a
      // second attempt after a successful one. Say so, instead of implying failure.
      if (!pending)
        throw new OAuthError(
          'there is no pending login from this gateway. If you already completed one, it succeeded — ' +
            'check `status` (or /healthz) instead of this page. Otherwise start a new login.',
        );
      if (!secretMatches(pending.state, returnedState || '')) throw new OAuthError('state mismatch — refusing the response');
      if (params.get('error'))
        throw new OAuthError(`authorization failed: ${params.get('error')} ${params.get('error_description') || ''}`.trim());
      if (!code) throw new OAuthError('the authorization server did not return a code');

      const current = await discover();
      const { tokenEndpoint } = pickEndpoints(current.metadata);
      const response = await exchangeCode({
        tokenEndpoint,
        clientId: state.clientId,
        code,
        redirectUri,
        verifier: pending.verifier,
        resource: current.resource,
        fetchImpl,
      });
      applyTokenResponse(state, response);
      save();
      pending = null;
      const description = describeState(state);
      pendingCompletion?.resolve(description);
      return description;
    } catch (error) {
      pendingCompletion?.reject(error);
      throw error;
    }
  }

  function openBrowser(url) {
    const [command, args] =
      process.platform === 'win32'
        ? ['cmd', ['/c', 'start', '', url]]
        : process.platform === 'darwin'
          ? ['open', [url]]
          : ['xdg-open', [url]];
    try {
      spawn(command, args, { detached: true, stdio: 'ignore' }).unref();
      return true;
    } catch {
      return false;
    }
  }

  // ------------------------------------------------------------------ request handling

  async function forward(req, res) {
    const token = await ensureToken();
    const headers = {};
    for (const [key, value] of Object.entries(req.headers)) {
      const lower = key.toLowerCase();
      // Drop hop-by-hop headers, the Host we are rewriting, any inbound credential, and our
      // own local token — none of those belong upstream.
      if (HOP_BY_HOP.has(lower) || lower === 'host' || lower === 'authorization' || lower === LOCAL_TOKEN_HEADER) continue;
      headers[key] = value;
    }
    headers.authorization = `Bearer ${token}`;
    headers.host = upstream.host;

    const target = new URL(upstream.toString());
    target.search = new URL(req.url, 'http://localhost').search;

    const upstreamReq = transportFor(target.protocol).request(
      {
        hostname: target.hostname,
        port: target.port || undefined,
        method: req.method,
        path: target.pathname + target.search,
        headers,
      },
      (upstreamRes) => {
        const outHeaders = {};
        for (const [key, value] of Object.entries(upstreamRes.headers)) {
          if (!HOP_BY_HOP.has(key.toLowerCase())) outHeaders[key] = value;
        }
        res.writeHead(upstreamRes.statusCode || 502, outHeaders);
        // Pipe, never buffer: SSE frames must flow through as they arrive.
        upstreamRes.pipe(res);
      },
    );
    upstreamReq.on('error', (error) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
        res.end(`upstream request failed: ${error.message}\n`);
      } else {
        res.destroy();
      }
    });
    // SSE connections are long-lived; do not impose a request timeout on them.
    upstreamReq.setTimeout(0);
    req.pipe(upstreamReq);
  }

  function sendJson(res, status, body) {
    const text = `${JSON.stringify(body, null, 2)}\n`;
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(text) });
    res.end(text);
  }

  const handler = async (req, res) => {
    const url = new URL(req.url, `http://${redirectHost}:${proxyPort}`);
    try {
      if (url.pathname === '/healthz') {
        return sendJson(res, 200, { ok: true, ...describeState(state), localUrl: `http://127.0.0.1:${proxyPort}${localPath}` });
      }

      if (url.pathname === redirectPath) {
        try {
          const description = await finishLogin(url.searchParams);
          log('login complete');
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
          return res.end(
            '<!doctype html><meta charset="utf-8"><title>Authorization complete</title>' +
              '<h1>Authorization complete</h1><p>You can close this tab and go back to your client.</p>' +
              `<pre>${escapeHtml(JSON.stringify(description, null, 2))}</pre>`,
          );
        } catch (error) {
          log(`login failed: ${error.message}`);
          res.writeHead(400, { 'content-type': 'text/html; charset=utf-8' });
          return res.end(`<!doctype html><meta charset="utf-8"><h1>Authorization failed</h1><pre>${escapeHtml(error.message)}</pre>`);
        }
      }

      if (url.pathname === '/oauth/login') {
        if (!authorizeMissingToken) return sendJson(res, 404, { error: 'login_disabled' });
        const authorizeUrl = await beginLogin();
        log(`open this URL to authorize:\n  ${authorizeUrl}`);
        openBrowser(authorizeUrl);
        if ((req.headers.accept || '').includes('application/json')) {
          return sendJson(res, 200, { authorizeUrl, redirectUri });
        }
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(
          '<!doctype html><meta charset="utf-8"><title>Authorize</title><h1>Authorize access</h1>' +
            `<p>If the browser did not open, follow this link:</p><p><a href="${escapeHtml(authorizeUrl)}">${escapeHtml(authorizeUrl)}</a></p>` +
            '<p><strong>Use the browser where you are already signed in to the authorization server.</strong> ' +
            'An embedded preview window or a browser without a session there will ask you to sign in, and ' +
            'that step often cannot complete inside a popup.</p>',
        );
      }

      if (url.pathname !== localPath) {
        return sendJson(res, 404, { error: 'not_found', message: `this gateway serves ${localPath} and ${redirectPath}` });
      }

      // Everything on the proxy path is for the real server; local callers must prove they
      // are allowed to use *our* credential.
      const presented = req.headers[LOCAL_TOKEN_HEADER] || url.searchParams.get('token');
      if (!secretMatches(localToken, presented)) {
        return sendJson(res, 401, {
          error: 'gateway_unauthorized',
          message: 'send the gateway token as the x-mcp-gateway-token header',
        });
      }

      return await forward(req, res);
    } catch (error) {
      const message = error instanceof OAuthError ? error.message : `${error.name}: ${error.message}`;
      log(`request failed: ${message}`);
      if (!res.headersSent) sendJson(res, 503, { error: 'gateway_error', message });
      else res.destroy();
    }
  };

  const listen = await listenLoopback(handler, proxyPort);
  return {
    proxyPort,
    redirectUri,
    localUrl: `http://127.0.0.1:${proxyPort}${localPath}`,
    localToken,
    beginLogin,
    finishLogin,
    refreshNow,
    ensureToken,
    openBrowser,
    /** Resolve when the browser comes back from the authorization server. */
    waitForLogin(timeoutMs = LOGIN_TIMEOUT_MS) {
      if (!pendingCompletion) return Promise.reject(new Error('no login is in progress'));
      const timer = setTimeout(() => pendingCompletion?.reject(new Error('timed out waiting for the browser redirect')), timeoutMs);
      timer.unref?.();
      return pendingCompletion.promise.finally(() => clearTimeout(timer));
    },
    describe: () => describeState(state),
    async stop() {
      await listen.close();
    },
  };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}

/**
 * Interactive login for the CLI: start the (loopback-only) gateway, print the URL, open the
 * browser, wait for the redirect, then stop. Returns the safe description of the credential.
 */
export async function login(options) {
  const { stateFile, log = () => {}, openBrowser: shouldOpenBrowser = true } = options;
  const gateway = await createGateway(options);
  try {
    const authorizeUrl = await gateway.beginLogin();
    log(
      `\nOpen this URL to authorize (in the browser where you are already signed in to the\n` +
        `authorization server — an embedded preview or popup window usually cannot sign in):\n  ${authorizeUrl}\n`,
    );
    if (shouldOpenBrowser) gateway.openBrowser(authorizeUrl);
    log(`waiting for the redirect on ${gateway.redirectUri} (Ctrl-C to abort) …`);
    const description = await gateway.waitForLogin(LOGIN_TIMEOUT_MS);
    log(`stored credentials in ${stateFile}`);
    return description;
  } finally {
    await gateway.stop();
  }
}
