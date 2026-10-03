// Genericity: confidential clients (a client secret) and server-specific extra parameters.
// Both are what stop the gateway being useful only against authorization servers that happen
// to accept a public PKCE client with no extra knobs.

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildAuthorizeUrl,
  chooseTokenAuthMethod,
  exchangeCode,
  refreshTokens,
  resolveClient,
} from '../src/oauth.mjs';
import { describeState, serverNameFor } from '../src/store.mjs';

function jsonResponse(body, { status = 200 } = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/** A fetch stub that keeps the call log, so headers and form bodies can both be asserted. */
function stubFetch(routes) {
  const calls = [];
  const impl = async (url, init = {}) => {
    const key = String(url);
    calls.push({ url: key, init, headers: init.headers || {}, body: new URLSearchParams(init.body || '') });
    const route = routes[key];
    if (!route) throw new Error(`unexpected fetch: ${key}`);
    return typeof route === 'function' ? route(init, calls.filter((c) => c.url === key).length - 1) : route.clone();
  };
  impl.calls = calls;
  return impl;
}

const TOKEN_URL = 'https://issuer.example/token';

test('chooseTokenAuthMethod honours an explicit choice, then the metadata, then Basic', () => {
  assert.equal(chooseTokenAuthMethod({ token_endpoint_auth_methods_supported: ['client_secret_post'] }, 'client_secret_basic'), 'client_secret_basic');
  assert.equal(chooseTokenAuthMethod({ token_endpoint_auth_methods_supported: ['client_secret_post'] }), 'client_secret_post');
  assert.equal(chooseTokenAuthMethod({ token_endpoint_auth_methods_supported: ['client_secret_basic'] }), 'client_secret_basic');
  assert.equal(
    chooseTokenAuthMethod({ token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'] }),
    'client_secret_basic',
  );
  // Absent or unhelpful metadata: Basic, because that is what major servers expect.
  assert.equal(chooseTokenAuthMethod({}), 'client_secret_basic');
  assert.equal(chooseTokenAuthMethod(undefined), 'client_secret_basic');
  assert.equal(chooseTokenAuthMethod({ token_endpoint_auth_methods_supported: ['none'] }), 'client_secret_basic');
});

test('a confidential client uses HTTP Basic and keeps client_id out of the body', async () => {
  const fetchImpl = stubFetch({ [TOKEN_URL]: jsonResponse({ access_token: 'at', refresh_token: 'rt' }) });
  await exchangeCode({
    tokenEndpoint: TOKEN_URL,
    clientId: 'client-1',
    clientSecret: 'sh-1',
    clientAuth: { clientId: 'client-1', clientSecret: 'sh-1', method: 'client_secret_basic' },
    code: 'code-1',
    redirectUri: 'http://localhost:33419/oauth/callback',
    verifier: 'verifier-1',
    fetchImpl,
  });
  const call = fetchImpl.calls[0];
  assert.equal(call.headers.authorization, `Basic ${Buffer.from('client-1:sh-1').toString('base64')}`);
  assert.equal(call.body.get('client_secret'), null, 'the secret must not also travel in the body');
  assert.equal(call.body.get('client_id'), null, 'RFC 6749 allows one authentication method per request');
  assert.equal(call.body.get('code'), 'code-1', 'the rest of the request is unchanged');
});

test('client_secret_post keeps the secret in the body and sends no Authorization header', async () => {
  const fetchImpl = stubFetch({ [TOKEN_URL]: jsonResponse({ access_token: 'at' }) });
  await exchangeCode({
    tokenEndpoint: TOKEN_URL,
    clientId: 'client-1',
    clientAuth: { clientId: 'client-1', clientSecret: 'sh-1', method: 'client_secret_post' },
    code: 'code-1',
    redirectUri: 'http://localhost:33419/oauth/callback',
    verifier: 'verifier-1',
    fetchImpl,
  });
  const call = fetchImpl.calls[0];
  assert.equal(call.headers.authorization, undefined);
  assert.equal(call.body.get('client_secret'), 'sh-1');
  assert.equal(call.body.get('client_id'), 'client-1');
});

test('a public client is unchanged: client_id in the body, no Authorization header', async () => {
  const fetchImpl = stubFetch({ [TOKEN_URL]: jsonResponse({ access_token: 'at' }) });
  await exchangeCode({
    tokenEndpoint: TOKEN_URL,
    clientId: 'client-1',
    code: 'code-1',
    redirectUri: 'http://localhost:33419/oauth/callback',
    verifier: 'verifier-1',
    clientAuth: { clientId: 'client-1' }, // no secret
    fetchImpl,
  });
  const call = fetchImpl.calls[0];
  assert.equal(call.headers.authorization, undefined);
  assert.equal(call.body.get('client_id'), 'client-1');
  assert.equal(call.body.get('client_secret'), null);
});

test('refresh also carries the secret, since silent renewal is what breaks without it', async () => {
  const fetchImpl = stubFetch({ [TOKEN_URL]: jsonResponse({ access_token: 'at-2' }) });
  await refreshTokens({
    tokenEndpoint: TOKEN_URL,
    clientId: 'client-1',
    refreshToken: 'rt-1',
    clientAuth: { clientId: 'client-1', clientSecret: 'sh-1', method: 'client_secret_basic' },
    fetchImpl,
  });
  const call = fetchImpl.calls[0];
  assert.equal(call.headers.authorization, `Basic ${Buffer.from('client-1:sh-1').toString('base64')}`);
  assert.equal(call.body.get('grant_type'), 'refresh_token');
  assert.equal(call.body.get('refresh_token'), 'rt-1');
});

test('extra parameters reach the authorization URL, and can override a standard one', () => {
  const url = new URL(
    buildAuthorizeUrl({
      authorizationEndpoint: 'https://issuer.example/authorize',
      clientId: 'client-1',
      redirectUri: 'http://localhost:33419/oauth/callback',
      state: 'st',
      challenge: 'ch',
      // The Google case: without access_type=offline there is no refresh token at all.
      extraParams: { access_type: 'offline', prompt: 'consent', scope: 'openid offline_access' },
    }),
  );
  assert.equal(url.searchParams.get('access_type'), 'offline');
  assert.equal(url.searchParams.get('prompt'), 'consent');
  assert.equal(url.searchParams.get('scope'), 'openid offline_access', 'extras win over the default scope');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256', 'the standard parameters survive');
});

test('extra parameters reach the token request too (Auth0 needs audience here)', async () => {
  const fetchImpl = stubFetch({ [TOKEN_URL]: jsonResponse({ access_token: 'at' }) });
  await exchangeCode({
    tokenEndpoint: TOKEN_URL,
    clientId: 'client-1',
    code: 'code-1',
    redirectUri: 'http://localhost:33419/oauth/callback',
    verifier: 'verifier-1',
    extraParams: { audience: 'https://api.example' },
    fetchImpl,
  });
  assert.equal(fetchImpl.calls[0].body.get('audience'), 'https://api.example');
});

test('a dynamically registered secret is returned so it can be persisted', async () => {
  const registrationEndpoint = 'https://issuer.example/register';
  const fetchImpl = stubFetch({
    [registrationEndpoint]: jsonResponse({
      client_id: 'dcr-1',
      client_secret: 'dcr-secret',
      token_endpoint_auth_method: 'client_secret_post',
    }),
  });
  const resolved = await resolveClient({
    metadata: { registration_endpoint: registrationEndpoint },
    redirectUri: 'http://localhost:33419/oauth/callback',
    fetchImpl,
  });
  assert.equal(resolved.clientId, 'dcr-1');
  assert.equal(resolved.clientSecret, 'dcr-secret');
  assert.equal(resolved.tokenAuthMethod, 'client_secret_post', 'the registration names its own method');

  const publicOnly = stubFetch({ [registrationEndpoint]: jsonResponse({ client_id: 'dcr-2' }) });
  const second = await resolveClient({
    metadata: { registration_endpoint: registrationEndpoint },
    redirectUri: 'http://localhost:33419/oauth/callback',
    fetchImpl: publicOnly,
  });
  assert.equal(second.clientSecret, undefined);
  assert.equal(second.tokenAuthMethod, undefined);
});

test('an explicitly configured client id skips registration entirely', async () => {
  const fetchImpl = stubFetch({});
  const resolved = await resolveClient({ metadata: {}, clientId: 'client-1', fetchImpl });
  assert.deepEqual(resolved, { clientId: 'client-1', dynamicallyRegistered: false });
  assert.equal(fetchImpl.calls.length, 0);
});

test('serverNameFor derives a DSH-safe name from any URL', () => {
  assert.equal(serverNameFor('https://openspec.panghuer.top/mcp'), 'openspec');
  assert.equal(serverNameFor('https://mcp.example.com/mcp'), 'mcp');
  assert.equal(serverNameFor('https://LOCALHOST:33419/mcp'), 'localhost');
  assert.equal(serverNameFor('https://weird-host_name.example/mcp'), 'weird-host_name');
  assert.equal(serverNameFor('https://a.b.c/mcp'), 'a');
  assert.equal(serverNameFor('not a url'), 'mcp');
  assert.equal(serverNameFor(''), 'mcp');
  assert.equal(serverNameFor(`https://${'x'.repeat(60)}.example/mcp`).length, 32, 'DSH caps the name at 32 chars');
  assert.match(serverNameFor('https://a--b.example/mcp'), /^[A-Za-z0-9_-]{1,32}$/);
});

test('describeState reports the secret without ever printing it', () => {
  const state = {
    mcpUrl: 'https://mcp.example/mcp',
    resource: 'https://mcp.example/mcp',
    authorizationServer: 'https://issuer.example/',
    clientId: 'client-1',
    clientSecret: 'super-secret-value',
    tokenAuthMethod: 'client_secret_basic',
    authorizeParams: { access_type: 'offline' },
    tokenParams: { audience: 'https://api.example' },
    tokens: { access_token: 'ACCESS-TOKEN-VALUE', refresh_token: 'REFRESH-TOKEN-VALUE', expires_at: Date.now() + 3600_000 },
  };
  const description = describeState(state);
  const printed = JSON.stringify(description);
  assert.equal(description.clientSecretPresent, true);
  assert.equal(description.tokenAuthMethod, 'client_secret_basic');
  assert.deepEqual(description.authorizeParams, ['access_type']);
  assert.deepEqual(description.tokenParams, ['audience'], 'the names are useful; the values are not printed');
  assert.ok(!printed.includes('super-secret-value'), 'the secret must never appear in `status`');
  assert.ok(!printed.includes('ACCESS-TOKEN-VALUE'), 'and neither must the access token');
  assert.ok(!printed.includes('REFRESH-TOKEN-VALUE'), 'nor the refresh token');
});
