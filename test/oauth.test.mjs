import assert from 'node:assert/strict';
import test from 'node:test';

import {
  OAuthError,
  buildAuthorizeUrl,
  challengeFor,
  createPkce,
  discoverMcp,
  exchangeCode,
  parseResourceMetadata,
  refreshTokens,
  registerClient,
  resolveClient,
  wellKnownCandidates,
} from '../src/oauth.mjs';

function jsonResponse(body, { status = 200, headers = {} } = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

/** A fetch stub: routes keyed by URL, call log attached, so nothing touches the network. */
function stubFetch(routes) {
  const calls = [];
  const impl = async (url, init = {}) => {
    const key = String(url);
    calls.push({ url: key, init });
    const route = routes[key];
    if (!route) throw new Error(`unexpected fetch: ${key}`);
    return typeof route === 'function' ? route(init) : route;
  };
  impl.calls = calls;
  return impl;
}

test('PKCE S256 matches the RFC 7636 appendix B vector', () => {
  assert.equal(
    challengeFor('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
    'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  );
});

test('createPkce produces an RFC 7636 compliant verifier and its challenge', () => {
  const { verifier, challenge } = createPkce();
  assert.match(verifier, /^[A-Za-z0-9._~-]{43,128}$/);
  assert.equal(challenge, challengeFor(verifier));
  assert.match(challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(createPkce().verifier, verifier);
});

test('parseResourceMetadata reads the RFC 9728 pointer out of a challenge', () => {
  assert.equal(
    parseResourceMetadata('Bearer resource_metadata="https://h/.well-known/oauth-protected-resource/mcp"'),
    'https://h/.well-known/oauth-protected-resource/mcp',
  );
  // Real servers vary: unquoted values and extra parameters both appear in the wild.
  assert.equal(parseResourceMetadata('Bearer resource_metadata=https://h/prm, error="invalid_token"'), 'https://h/prm');
  assert.equal(parseResourceMetadata('Bearer realm="x", resource_metadata="https://h/prm"'), 'https://h/prm');
  assert.equal(parseResourceMetadata('Bearer realm="x"'), null);
  assert.equal(parseResourceMetadata('Basic realm="x"'), null);
  assert.equal(parseResourceMetadata(undefined), null);
});

test('wellKnownCandidates covers the RFC 8414 insertion and the plain form', () => {
  assert.deepEqual(wellKnownCandidates('https://issuer.example'), [
    'https://issuer.example/.well-known/oauth-authorization-server',
    'https://issuer.example/.well-known/openid-configuration',
  ]);
  const withPath = wellKnownCandidates('https://issuer.example/tenant/');
  assert.ok(withPath.includes('https://issuer.example/.well-known/oauth-authorization-server/tenant'));
  assert.ok(withPath.includes('https://issuer.example/tenant/.well-known/oauth-authorization-server'));
  assert.equal(new Set(withPath).size, withPath.length, 'candidates must be de-duplicated');
});

test('buildAuthorizeUrl carries PKCE, state, scope and the RFC 8707 resource', () => {
  const url = new URL(
    buildAuthorizeUrl({
      authorizationEndpoint: 'https://issuer.example/authorize',
      clientId: 'client-1',
      redirectUri: 'http://localhost:33419/oauth/callback',
      state: 'st-1',
      challenge: 'ch-1',
      resource: 'https://mcp.example/mcp',
      scopes: ['openid', 'email'],
    }),
  );
  assert.equal(url.origin + url.pathname, 'https://issuer.example/authorize');
  const q = url.searchParams;
  assert.equal(q.get('response_type'), 'code');
  assert.equal(q.get('client_id'), 'client-1');
  assert.equal(q.get('redirect_uri'), 'http://localhost:33419/oauth/callback');
  assert.equal(q.get('scope'), 'openid email');
  assert.equal(q.get('state'), 'st-1');
  assert.equal(q.get('code_challenge'), 'ch-1');
  assert.equal(q.get('code_challenge_method'), 'S256');
  assert.equal(q.get('resource'), 'https://mcp.example/mcp');
  // A token endpoint may already carry a query string of its own; the authorize URL must not.
  const withQuery = new URL(
    buildAuthorizeUrl({
      authorizationEndpoint: 'https://issuer.example/authorize?tenant=a',
      clientId: 'c',
      redirectUri: 'http://localhost:1/cb',
      state: 's',
      challenge: 'x',
    }),
  );
  assert.equal(withQuery.searchParams.get('tenant'), 'a');
  assert.equal(withQuery.searchParams.get('client_id'), 'c');
  assert.equal(withQuery.searchParams.get('resource'), null, 'no resource means no parameter');
});

test('exchangeCode posts the verifier and surfaces an authorization server error', async () => {
  const ok = stubFetch({
    'https://issuer.example/token': (init) => {
      assert.equal(init.method, 'POST');
      assert.match(init.headers['content-type'], /application\/x-www-form-urlencoded/);
      const params = new URLSearchParams(init.body);
      assert.equal(params.get('grant_type'), 'authorization_code');
      assert.equal(params.get('code'), 'the-code');
      assert.equal(params.get('code_verifier'), 'the-verifier');
      assert.equal(params.get('redirect_uri'), 'http://localhost:1/cb');
      assert.equal(params.get('resource'), 'https://mcp.example/mcp');
      return jsonResponse({ access_token: 'at', refresh_token: 'rt', expires_in: 3600 });
    },
  });
  const tokens = await exchangeCode({
    tokenEndpoint: 'https://issuer.example/token',
    clientId: 'c1',
    code: 'the-code',
    redirectUri: 'http://localhost:1/cb',
    verifier: 'the-verifier',
    resource: 'https://mcp.example/mcp',
    fetchImpl: ok,
  });
  assert.equal(tokens.access_token, 'at');

  const failing = stubFetch({
    'https://issuer.example/token': () => jsonResponse({ error: 'invalid_grant', error_description: 'code expired' }, { status: 400 }),
  });
  await assert.rejects(
    () => exchangeCode({ tokenEndpoint: 'https://issuer.example/token', clientId: 'c', code: 'x', redirectUri: 'http://l/cb', verifier: 'v', fetchImpl: failing }),
    (error) => error instanceof OAuthError && /invalid_grant: code expired/.test(error.message),
  );
});

test('refreshTokens sends the refresh grant with the resource', async () => {
  const impl = stubFetch({
    'https://issuer.example/token': (init) => {
      const params = new URLSearchParams(init.body);
      assert.equal(params.get('grant_type'), 'refresh_token');
      assert.equal(params.get('refresh_token'), 'rt-1');
      assert.equal(params.get('resource'), 'https://mcp.example/mcp');
      return jsonResponse({ access_token: 'at-2', expires_in: 60 });
    },
  });
  const tokens = await refreshTokens({
    tokenEndpoint: 'https://issuer.example/token',
    clientId: 'c1',
    refreshToken: 'rt-1',
    resource: 'https://mcp.example/mcp',
    fetchImpl: impl,
  });
  assert.equal(tokens.access_token, 'at-2');
});

test('resolveClient uses a configured client id and never registers', async () => {
  const impl = stubFetch({});
  const result = await resolveClient({
    metadata: { registration_endpoint: 'https://issuer.example/register' },
    clientId: 'known-id',
    redirectUri: 'http://localhost:1/cb',
    fetchImpl: impl,
  });
  assert.deepEqual(result, { clientId: 'known-id', dynamicallyRegistered: false });
  assert.equal(impl.calls.length, 0);
});

test('resolveClient explains the manual path when the server has no registration endpoint', async () => {
  await assert.rejects(
    () => resolveClient({ metadata: {}, redirectUri: 'http://localhost:33419/oauth/callback', fetchImpl: stubFetch({}) }),
    (error) =>
      error instanceof OAuthError &&
      /--client-id/.test(error.message) &&
      error.message.includes('http://localhost:33419/oauth/callback'),
  );
});

test('resolveClient turns a rejected registration into instructions, not a stack trace', async () => {
  const impl = stubFetch({
    'https://issuer.example/register': () =>
      jsonResponse(
        { error: 'invalid_client_metadata', error_description: 'dynamic client registration is disabled for this organization' },
        { status: 400 },
      ),
  });
  await assert.rejects(
    () => resolveClient({ metadata: { registration_endpoint: 'https://issuer.example/register' }, redirectUri: 'http://l/cb', fetchImpl: impl }),
    (error) =>
      error instanceof OAuthError &&
      /dynamic client registration is disabled/.test(error.message) &&
      /no client secret is needed/.test(error.message),
  );
});

test('discoverMcp walks 401 -> PRM -> authorization server metadata', async () => {
  const impl = stubFetch({
    'https://mcp.example/mcp': () =>
      jsonResponse({}, { status: 401, headers: { 'www-authenticate': 'Bearer resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/mcp"' } }),
    'https://mcp.example/.well-known/oauth-protected-resource/mcp': () =>
      jsonResponse({ resource: 'https://mcp.example/mcp', authorization_servers: ['https://issuer.example'] }),
    'https://issuer.example/.well-known/oauth-authorization-server': () =>
      jsonResponse({ authorization_endpoint: 'https://issuer.example/authorize', token_endpoint: 'https://issuer.example/token' }),
  });
  const discovered = await discoverMcp('https://mcp.example/mcp', { fetchImpl: impl });
  assert.equal(discovered.resource, 'https://mcp.example/mcp');
  assert.equal(discovered.authorizationServer, 'https://issuer.example/');
  assert.equal(discovered.metadata.token_endpoint, 'https://issuer.example/token');
});

test('discoverMcp falls back to openid-configuration when RFC 8414 metadata is missing', async () => {
  const impl = stubFetch({
    'https://mcp.example/mcp': () =>
      jsonResponse({}, { status: 401, headers: { 'www-authenticate': 'Bearer resource_metadata="https://mcp.example/prm"' } }),
    'https://mcp.example/prm': () => jsonResponse({ authorization_servers: ['https://issuer.example'] }),
    'https://issuer.example/.well-known/oauth-authorization-server': () => new Response('nope', { status: 404 }),
    'https://issuer.example/.well-known/openid-configuration': () =>
      jsonResponse({ authorization_endpoint: 'https://issuer.example/authorize', token_endpoint: 'https://issuer.example/token' }),
  });
  const discovered = await discoverMcp('https://mcp.example/mcp', { fetchImpl: impl });
  assert.equal(discovered.resource, 'https://mcp.example/mcp', 'resource falls back to the MCP URL');
  assert.equal(discovered.metadata.authorization_endpoint, 'https://issuer.example/authorize');
});

test('discoverMcp gives an actionable error for a 401 with no PRM pointer', async () => {
  const impl = stubFetch({ 'https://mcp.example/mcp': () => jsonResponse({}, { status: 401 }) });
  await assert.rejects(
    () => discoverMcp('https://mcp.example/mcp', { fetchImpl: impl }),
    (error) => error instanceof OAuthError && /--authorization-server/.test(error.message),
  );
});

test('discoverMcp says so when the endpoint needs no authorization at all', async () => {
  const impl = stubFetch({ 'https://mcp.example/mcp': () => jsonResponse({ result: {} }, { status: 200 }) });
  await assert.rejects(
    () => discoverMcp('https://mcp.example/mcp', { fetchImpl: impl }),
    (error) => error instanceof OAuthError && /nothing to authorize/.test(error.message),
  );
});

test('registerClient asks for a public client (PKCE, no secret)', async () => {
  let body;
  const impl = stubFetch({
    'https://issuer.example/register': (init) => {
      body = JSON.parse(init.body);
      return jsonResponse({ client_id: 'dcr-1' }, { status: 201 });
    },
  });
  const registration = await registerClient({
    registrationEndpoint: 'https://issuer.example/register',
    redirectUri: 'http://localhost:33419/oauth/callback',
    fetchImpl: impl,
  });
  assert.equal(registration.client_id, 'dcr-1');
  assert.equal(body.token_endpoint_auth_method, 'none');
  assert.deepEqual(body.redirect_uris, ['http://localhost:33419/oauth/callback']);
  assert.deepEqual(body.grant_types, ['authorization_code', 'refresh_token']);
});
