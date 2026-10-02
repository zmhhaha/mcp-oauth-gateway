import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createGateway, effectiveExpiryMs, transportFor } from '../src/gateway.mjs';
import { saveState, storeFileFor } from '../src/store.mjs';

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

/** A fake MCP server that records what it was sent. */
function startUpstream(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

async function startGateway({ upstreamPort, tokens, localToken = 'local-secret' }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-oauth-gateway-'));
  const mcpUrl = `http://127.0.0.1:${upstreamPort}/mcp`;
  const stateFile = storeFileFor(mcpUrl, dir);
  const state = { version: 1, mcpUrl, localToken, tokens };
  saveState(stateFile, state);
  const gateway = await createGateway({ mcpUrl, state, stateFile, proxyPort: await freePort(), log: () => {} });
  return {
    gateway,
    state,
    cleanup: async () => {
      await gateway.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

const FRESH_TOKENS = () => ({ access_token: 'oauth-access-token', expires_at: Date.now() + 3_600_000 });

test('effectiveExpiryMs prefers the stored expiry and falls back to the JWT exp', () => {  assert.equal(effectiveExpiryMs({}), null);
  assert.equal(effectiveExpiryMs({ tokens: { access_token: 'x' } }), null);
  assert.equal(effectiveExpiryMs({ tokens: { access_token: 'x', expires_at: 42 } }), 42);

  const payload = Buffer.from(JSON.stringify({ exp: 1_700_000_000 })).toString('base64url');
  const jwt = `header.${payload}.signature`;
  assert.equal(effectiveExpiryMs({ tokens: { access_token: jwt } }), 1_700_000_000_000);
});

test('the proxy picks its transport by the upstream scheme', () => {
  // node:http throws `Protocol "https:" not supported. Expected "http:"`, and https is the
  // usual case for a real MCP endpoint — an http-only test server hides the mistake.
  assert.equal(transportFor('https:'), https);
  assert.equal(transportFor('http:'), http);
});

test('the proxy rejects a caller without the gateway token and does not touch the upstream', async () => {
  let upstreamHits = 0;
  const { server, port } = await startUpstream((_req, res) => {
    upstreamHits += 1;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  const { gateway, cleanup } = await startGateway({ upstreamPort: port, tokens: FRESH_TOKENS() });
  try {
    for (const headers of [{}, { 'x-mcp-gateway-token': 'wrong' }]) {
      const res = await fetch(gateway.localUrl, { method: 'POST', headers, body: '{}' });
      assert.equal(res.status, 401);
      assert.equal((await res.json()).error, 'gateway_unauthorized');
    }
    assert.equal(upstreamHits, 0, 'an unauthenticated caller must never reach the MCP server');
  } finally {
    await cleanup();
    server.close();
  }
});

test('the proxy injects the OAuth token and forwards the request untouched otherwise', async () => {
  const seen = [];
  const { server, port } = await startUpstream((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
      res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': 'session-1' });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  const { gateway, cleanup } = await startGateway({ upstreamPort: port, tokens: FRESH_TOKENS() });
  try {
    const res = await fetch(`${gateway.localUrl}?trace=1`, {
      method: 'POST',
      headers: { 'x-mcp-gateway-token': gateway.localToken, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('mcp-session-id'), 'session-1', 'upstream response headers survive');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].method, 'POST');
    assert.equal(seen[0].url, '/mcp?trace=1', 'the path and query reach the upstream endpoint');
    assert.equal(seen[0].headers.authorization, 'Bearer oauth-access-token', 'the OAuth token is injected for the upstream');
    assert.equal(seen[0].headers['x-mcp-gateway-token'], undefined, 'the local token must not leak upstream');
    assert.match(seen[0].body, /tools\/list/, 'the request body is forwarded');
  } finally {
    await cleanup();
    server.close();
  }
});

test('SSE responses are streamed, not buffered', async () => {
  const { server, port } = await startUpstream((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
    res.write('event: message\ndata: one\n\n');
    // A buffering proxy would hold "one" until this fires, which is exactly the bug we guard against.
    setTimeout(() => {
      res.write('event: message\ndata: two\n\n');
      res.end();
    }, 250).unref();
  });
  const { gateway, cleanup } = await startGateway({ upstreamPort: port, tokens: FRESH_TOKENS() });
  try {
    const res = await fetch(gateway.localUrl, {
      method: 'POST',
      headers: { 'x-mcp-gateway-token': gateway.localToken, accept: 'text/event-stream' },
      body: '{}',
    });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/event-stream/);

    const reader = res.body.getReader();
    const startedAt = Date.now();
    const { value: first } = await reader.read();
    const firstChunkAt = Date.now();
    let rest = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      rest += Buffer.from(value).toString();
    }
    const finishedAt = Date.now();

    assert.match(Buffer.from(first).toString(), /data: one/);
    assert.match(rest, /data: two/);
    assert.ok(
      firstChunkAt - startedAt < finishedAt - firstChunkAt,
      `the first frame must arrive well before the stream ends (first=${firstChunkAt - startedAt}ms, total=${finishedAt - startedAt}ms)`,
    );
  } finally {
    await cleanup();
    server.close();
  }
});

test('/healthz reports state without a token and without leaking secrets', async () => {
  const { server, port } = await startUpstream((_req, res) => res.end());
  const { gateway, cleanup } = await startGateway({
    upstreamPort: port,
    tokens: { access_token: 'secret-access', refresh_token: 'secret-refresh', expires_at: Date.now() + 1000 },
  });
  try {
    const res = await fetch(`http://127.0.0.1:${gateway.proxyPort}/healthz`);
    assert.equal(res.status, 200);
    const text = await res.text();
    assert.ok(!text.includes('secret-access') && !text.includes('secret-refresh') && !text.includes(gateway.localToken));
    assert.match(text, /"status":/);
  } finally {
    await cleanup();
    server.close();
  }
});

test('an unknown path is refused with a pointer to the served paths', async () => {
  const { server, port } = await startUpstream((_req, res) => res.end());
  const { gateway, cleanup } = await startGateway({ upstreamPort: port, tokens: FRESH_TOKENS() });
  try {
    const res = await fetch(`http://127.0.0.1:${gateway.proxyPort}/something-else`);
    assert.equal(res.status, 404);
    assert.deepEqual(Object.keys(await res.json()).sort(), ['error', 'message']);
  } finally {
    await cleanup();
    server.close();
  }
});

test('a missing credential produces a 503 that tells the user how to log in', async () => {
  const { server, port } = await startUpstream((_req, res) => res.end());
  const { gateway, cleanup } = await startGateway({ upstreamPort: port, tokens: undefined });
  try {
    const res = await fetch(gateway.localUrl, { method: 'POST', headers: { 'x-mcp-gateway-token': gateway.localToken }, body: '{}' });
    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.error, 'gateway_error');
    assert.match(body.message, /oauth\/login|`login`/);
  } finally {
    await cleanup();
    server.close();
  }
});
