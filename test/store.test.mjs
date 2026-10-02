import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  EXPIRY_SKEW_MS,
  applyTokenResponse,
  defaultStoreDir,
  describeState,
  ensureLocalToken,
  loadState,
  saveState,
  storeFileFor,
  tokenStatus,
} from '../src/store.mjs';

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-oauth-gateway-test-'));
}

test('storeFileFor is deterministic per URL and distinct across URLs', () => {
  const dir = tempDir();
  const a = storeFileFor('https://one.example/mcp', dir);
  assert.equal(a, storeFileFor('https://one.example/mcp', dir));
  assert.notEqual(a, storeFileFor('https://two.example/mcp', dir));
  assert.ok(a.startsWith(dir));
  assert.match(path.basename(a), /^[0-9a-f]{16}\.json$/);
});

test('defaultStoreDir honours the environment override', () => {
  assert.equal(defaultStoreDir({ MCP_OAUTH_GATEWAY_STORE: '/tmp/custom' }), '/tmp/custom');
  assert.match(defaultStoreDir({ APPDATA: 'C:\\Users\\x\\AppData\\Roaming' }), /mcp-oauth-gateway$/);
});

test('state survives a save/load round trip and is written 0600 where supported', () => {
  const dir = tempDir();
  const file = storeFileFor('https://one.example/mcp', dir);
  saveState(file, { version: 1, mcpUrl: 'https://one.example/mcp', tokens: { access_token: 'at' } });
  assert.equal(loadState(file).tokens.access_token, 'at');
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  }
  // An atomic write leaves no temp files behind.
  assert.deepEqual(fs.readdirSync(dir), [path.basename(file)]);
});

test('loadState returns null for a missing file instead of throwing', () => {
  assert.equal(loadState(path.join(tempDir(), 'nope.json')), null);
});

test('applyTokenResponse computes expiry and preserves a refresh token the server omits', () => {
  const state = { tokens: { access_token: 'old', refresh_token: 'rt-keep' } };
  applyTokenResponse(state, { access_token: 'new', expires_in: 3600 }, 1_000_000);
  assert.equal(state.tokens.access_token, 'new');
  assert.equal(state.tokens.refresh_token, 'rt-keep');
  assert.equal(state.tokens.expires_at, 1_000_000 + 3_600_000);
  assert.equal(state.tokens.obtained_at, 1_000_000);

  // A rotated refresh token replaces the old one.
  applyTokenResponse(state, { access_token: 'newer', refresh_token: 'rt-2', expires_in: 60 }, 2_000_000);
  assert.equal(state.tokens.refresh_token, 'rt-2');

  // No expires_in: keep the previous expiry rather than inventing one.
  applyTokenResponse(state, { access_token: 'newest' }, 3_000_000);
  assert.equal(state.tokens.expires_at, 2_000_000 + 60_000);
});

test('applyTokenResponse leaves expiry null when the server declares no lifetime', () => {
  const state = {};
  applyTokenResponse(state, { access_token: 'at', token_type: 'Bearer' }, 5_000);
  assert.equal(state.tokens.expires_at, null);
  assert.equal(state.tokens.token_type, 'Bearer');
  assert.equal(tokenStatus(state), 'fresh', 'an unknown lifetime is the server\'s business');
});

test('tokenStatus distinguishes fresh, refreshable, expired and missing', () => {
  const now = 1_000_000;
  assert.equal(tokenStatus({}, { now }), 'missing');
  assert.equal(tokenStatus({ tokens: { access_token: 'a', expires_at: now + 600_000 } }, { now }), 'fresh');
  assert.equal(
    tokenStatus({ tokens: { access_token: 'a', expires_at: now + EXPIRY_SKEW_MS - 1, refresh_token: 'r' } }, { now }),
    'refreshable',
    'inside the skew window it is time to refresh',
  );
  assert.equal(tokenStatus({ tokens: { access_token: 'a', expires_at: now - 1 } }, { now }), 'expired');
  assert.equal(tokenStatus({ tokens: { access_token: 'a', expires_at: now - 1, refresh_token: 'r' } }, { now }), 'refreshable');
});

test('ensureLocalToken is stable and independent of the OAuth token', () => {
  const state = {};
  const first = ensureLocalToken(state);
  assert.equal(ensureLocalToken(state), first, 'a second call must not rotate the local token');
  assert.ok(first.length >= 32);
  applyTokenResponse(state, { access_token: 'at', expires_in: 60 }, 1);
  assert.equal(state.localToken, first, 'refreshing the OAuth token must not touch the local token');
});

test('describeState never exposes a token', () => {
  const state = {
    mcpUrl: 'https://one.example/mcp',
    resource: 'https://one.example/mcp',
    authorizationServer: 'https://issuer.example',
    clientId: 'c1',
    localToken: 'local-secret-value',
    tokens: { access_token: 'super-secret-token', refresh_token: 'super-secret-refresh', expires_at: 2_000_000, scope: 'openid' },
  };
  const serialized = JSON.stringify(describeState(state, { now: 1_000_000 }));
  assert.ok(!serialized.includes('super-secret-token'));
  assert.ok(!serialized.includes('super-secret-refresh'));
  assert.ok(!serialized.includes('local-secret-value'));
  assert.match(serialized, /"refreshTokenPresent":true/);
  assert.match(serialized, /"status":"fresh"/);
  assert.match(serialized, /"expiresAt":"1970-01-01T00:33:20.000Z"/);
});
