// RFC 8628 device authorization: the browserless login path.
//
// Everything here runs against a stubbed fetch and an injected clock/sleep, so the suite
// never touches the network and never actually waits.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  OAuthError,
  normalizeDeviceAuthorization,
  pollDeviceToken,
  requestDeviceCode,
} from '../src/oauth.mjs';
import { loginWithDeviceCode } from '../src/gateway.mjs';
import { ensureLocalToken } from '../src/store.mjs';

const MCP_URL = 'https://mcp.example/mcp';
const PRM_URL = 'https://mcp.example/.well-known/oauth-protected-resource';
const ISSUER = 'https://issuer.example';
const AS_METADATA_URL = `${ISSUER}/.well-known/oauth-authorization-server`;
const DEVICE_URL = `${ISSUER}/device`;
const TOKEN_URL = `${ISSUER}/token`;

function jsonResponse(body, { status = 200, headers = {} } = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

/** A fetch stub: routes keyed by URL; a function route also receives its own call index. */
function stubFetch(routes) {
  const calls = [];
  const impl = async (url, init = {}) => {
    const key = String(url);
    calls.push({ url: key, init });
    const route = routes[key];
    if (!route) throw new Error(`unexpected fetch: ${key}`);
    const index = calls.filter((call) => call.url === key).length - 1;
    // A Response body can only be read once, so a reused route must hand out a fresh clone.
    return typeof route === 'function' ? route(init, index) : route.clone();
  };
  impl.calls = calls;
  return impl;
}

const DEVICE_BODY = {
  device_code: 'dc-1',
  user_code: 'WDJB-MJHT',
  verification_uri: `${ISSUER}/device/verify`,
  verification_uri_complete: `${ISSUER}/device/verify?user_code=WDJB-MJHT`,
  expires_in: 600,
  interval: 1,
};

function discoveryRoutes(extra = {}) {
  return {
    [MCP_URL]: () =>
      new Response('', {
        status: 401,
        headers: { 'www-authenticate': `Bearer resource_metadata="${PRM_URL}"` },
      }),
    [PRM_URL]: jsonResponse({ resource: MCP_URL, authorization_servers: [ISSUER] }),
    [AS_METADATA_URL]: jsonResponse({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: TOKEN_URL,
      device_authorization_endpoint: DEVICE_URL,
    }),
    ...extra,
  };
}

/** A clock a test drives by hand, so expiry logic is exercised without waiting. */
function fakeClock() {
  let now = 0;
  return {
    now: () => now,
    sleep: async (ms) => {
      now += ms;
    },
    advance: (ms) => {
      now += ms;
    },
  };
}

test('normalizeDeviceAuthorization accepts the RFC field names and the camelCase ones', () => {
  const standard = normalizeDeviceAuthorization(DEVICE_BODY);
  assert.equal(standard.deviceCode, 'dc-1');
  assert.equal(standard.userCode, 'WDJB-MJHT');
  assert.equal(standard.verificationUri, `${ISSUER}/device/verify`);
  assert.equal(standard.verificationUriComplete, `${ISSUER}/device/verify?user_code=WDJB-MJHT`);
  assert.equal(standard.expiresInSeconds, 600);
  assert.equal(standard.intervalSeconds, 1);

  const camel = normalizeDeviceAuthorization({
    deviceCode: 'dc-2',
    userCode: 'AAAA-BBBB',
    verificationUri: 'https://issuer.example/verify',
    expiresIn: 900,
  });
  assert.equal(camel.deviceCode, 'dc-2');
  assert.equal(camel.userCode, 'AAAA-BBBB');
  assert.equal(camel.expiresInSeconds, 900);
  assert.equal(camel.intervalSeconds, 5, 'a missing interval falls back to the RFC minimum');

  assert.throws(() => normalizeDeviceAuthorization({ user_code: 'X' }), OAuthError);
  assert.throws(() => normalizeDeviceAuthorization({}), /device_code\/user_code/);
});

test('requestDeviceCode posts client_id, scope and the RFC 8707 resource', async () => {
  const fetchImpl = stubFetch({ [DEVICE_URL]: jsonResponse(DEVICE_BODY) });
  const body = await requestDeviceCode({
    deviceAuthorizationEndpoint: DEVICE_URL,
    clientId: 'client-1',
    scope: ['openid', 'email'],
    resource: MCP_URL,
    fetchImpl,
  });
  assert.equal(body.device_code, 'dc-1');
  const sent = new URLSearchParams(fetchImpl.calls[0].init.body);
  assert.equal(sent.get('client_id'), 'client-1');
  assert.equal(sent.get('scope'), 'openid email');
  assert.equal(sent.get('resource'), MCP_URL);
});

test('requestDeviceCode surfaces the server refusal verbatim', async () => {
  const fetchImpl = stubFetch({
    [DEVICE_URL]: jsonResponse(
      { error: 'unauthorized_client', error_description: 'device login is not enabled' },
      { status: 400 },
    ),
  });
  await assert.rejects(
    () =>
      requestDeviceCode({ deviceAuthorizationEndpoint: DEVICE_URL, clientId: 'c', fetchImpl }),
    (error) => {
      assert.equal(error.code, 'unauthorized_client');
      assert.match(error.message, /device authorization request failed/);
      assert.match(error.message, /device login is not enabled/);
      return true;
    },
  );
});

test('pollDeviceToken waits through authorization_pending and returns the tokens', async () => {
  const fetchImpl = stubFetch({
    [TOKEN_URL]: (_init, index) =>
      index === 0
        ? jsonResponse({ error: 'authorization_pending' }, { status: 400 })
        : jsonResponse({ access_token: 'at', refresh_token: 'rt', expires_in: 3600 }),
  });
  const waits = [];
  const tokens = await pollDeviceToken({
    tokenEndpoint: TOKEN_URL,
    clientId: 'client-1',
    deviceCode: 'dc-1',
    intervalSeconds: 1,
    expiresInSeconds: 600,
    fetchImpl,
    sleep: async (ms) => waits.push(ms),
    onWait: (info) => waits.push(info.intervalMs),
  });
  assert.equal(tokens.access_token, 'at');
  assert.equal(fetchImpl.calls.length, 2);
  const grant = new URLSearchParams(fetchImpl.calls[1].init.body);
  assert.equal(grant.get('grant_type'), 'urn:ietf:params:oauth:grant-type:device_code');
  assert.equal(grant.get('device_code'), 'dc-1');
  assert.deepEqual(waits, [1000, 1000], 'the RFC minimum interval is used');
});

test('pollDeviceToken widens the interval by 5s on slow_down, as RFC 8628 requires', async () => {
  const fetchImpl = stubFetch({
    [TOKEN_URL]: (_init, index) => {
      if (index === 0) return jsonResponse({ error: 'slow_down' }, { status: 400 });
      if (index === 1) return jsonResponse({ error: 'authorization_pending' }, { status: 400 });
      return jsonResponse({ access_token: 'at', expires_in: 3600 });
    },
  });
  const waits = [];
  await pollDeviceToken({
    tokenEndpoint: TOKEN_URL,
    clientId: 'client-1',
    deviceCode: 'dc-1',
    intervalSeconds: 1,
    expiresInSeconds: 600,
    fetchImpl,
    sleep: async (ms) => waits.push(ms),
  });
  assert.deepEqual(waits, [6000, 6000]);
});

test('pollDeviceToken rethrows a final error instead of retrying', async () => {
  const fetchImpl = stubFetch({
    [TOKEN_URL]: jsonResponse(
      { error: 'access_denied', error_description: 'the user refused' },
      { status: 400 },
    ),
  });
  await assert.rejects(
    () =>
      pollDeviceToken({
        tokenEndpoint: TOKEN_URL,
        clientId: 'client-1',
        deviceCode: 'dc-1',
        fetchImpl,
        sleep: async () => {},
      }),
    (error) => {
      assert.equal(error.code, 'access_denied');
      assert.match(error.message, /the user refused/);
      return true;
    },
  );
  assert.equal(fetchImpl.calls.length, 1, 'a refusal must not be polled again');
});

test('pollDeviceToken gives up when the device code expires', async () => {
  const fetchImpl = stubFetch({
    [TOKEN_URL]: jsonResponse({ error: 'authorization_pending' }, { status: 400 }),
  });
  const clock = fakeClock();
  await assert.rejects(
    () =>
      pollDeviceToken({
        tokenEndpoint: TOKEN_URL,
        clientId: 'client-1',
        deviceCode: 'dc-1',
        intervalSeconds: 1,
        expiresInSeconds: 3,
        fetchImpl,
        now: clock.now,
        sleep: clock.sleep,
      }),
    (error) => {
      assert.equal(error.code, 'expired_token');
      assert.match(error.message, /expired/);
      return true;
    },
  );
  assert.ok(fetchImpl.calls.length >= 2, 'it polled more than once before giving up');
});

test('loginWithDeviceCode stores the tokens and reports the code the human must enter', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-oauth-device-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const stateFile = path.join(dir, 'state.json');
  const state = { version: 1, mcpUrl: MCP_URL };
  ensureLocalToken(state);

  const fetchImpl = stubFetch(
    discoveryRoutes({
      [DEVICE_URL]: jsonResponse(DEVICE_BODY),
      [TOKEN_URL]: (_init, index) =>
        index === 0
          ? jsonResponse({ error: 'authorization_pending' }, { status: 400 })
          : jsonResponse({ access_token: 'at-1', refresh_token: 'rt-1', expires_in: 3600 }),
    }),
  );
  const clock = fakeClock();
  const logged = [];

  const description = await loginWithDeviceCode({
    mcpUrl: MCP_URL,
    state,
    stateFile,
    clientId: 'client-1',
    fetchImpl,
    now: clock.now,
    sleep: clock.sleep,
    log: (message) => logged.push(message),
  });

  assert.equal(description.device.userCode, 'WDJB-MJHT');
  assert.equal(description.device.verificationUriComplete, `${ISSUER}/device/verify?user_code=WDJB-MJHT`);
  assert.ok(
    logged.join('\n').includes('WDJB-MJHT'),
    'the human-readable instructions must contain the code',
  );

  const saved = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  assert.equal(saved.tokens.access_token, 'at-1');
  assert.equal(saved.tokens.refresh_token, 'rt-1');
  assert.equal(saved.clientId, 'client-1');
  assert.equal(saved.resource, MCP_URL);
  assert.equal(saved.authorizationServer, `${ISSUER}/`);
  assert.ok(saved.localToken, 'the stable local token is still minted');

  const deviceCall = fetchImpl.calls.find((call) => call.url === DEVICE_URL);
  assert.equal(new URLSearchParams(deviceCall.init.body).get('client_id'), 'client-1');
});

test('loginWithDeviceCode explains itself when the server has no device endpoint', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-oauth-device-'));
  const fetchImpl = stubFetch({
    ...discoveryRoutes({
      [AS_METADATA_URL]: jsonResponse({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: TOKEN_URL,
      }),
    }),
  });
  await assert.rejects(
    () =>
      loginWithDeviceCode({
        mcpUrl: MCP_URL,
        state: { version: 1, mcpUrl: MCP_URL },
        stateFile: path.join(dir, 'state.json'),
        clientId: 'client-1',
        fetchImpl,
      }),
    /does not advertise a device_authorization_endpoint/,
  );
  fs.rmSync(dir, { recursive: true, force: true });
});
