// Command line interface.
//
//   mcp-oauth-gateway login        --url <mcp-url> [--client-id <id>]
//   mcp-oauth-gateway serve        --url <mcp-url> [--port 33419]
//   mcp-oauth-gateway status       --url <mcp-url>
//   mcp-oauth-gateway refresh      --url <mcp-url>
//   mcp-oauth-gateway print-config --url <mcp-url> [--port 33419]
//   mcp-oauth-gateway logout       --url <mcp-url>
//
// Dependency-free on purpose: Node >= 20 gives us fetch, node:test and node:http.

import fs from 'node:fs';

import { OAuthError } from './oauth.mjs';
import { createGateway, login, loginWithDeviceCode } from './gateway.mjs';
import {
  defaultStoreDir,
  describeState,
  ensureLocalToken,
  loadState,
  saveState,
  serverNameFor,
  storeFileFor,
} from './store.mjs';

const USAGE = `mcp-oauth-gateway — OAuth 2.1 for MCP clients that only speak a static header

Usage
  mcp-oauth-gateway <command> --url <mcp-url> [options]

Commands
  login          Authorize and store the tokens (refresh token included)
                 add --device on a host with no browser (RFC 8628 device flow)
  serve          Run the loopback gateway; point your MCP client at the printed URL
  status         Show the stored credential (never prints the tokens themselves)
  refresh        Force a token refresh now (useful from a scheduled task)
  print-config   Print ready-to-paste client configuration
  logout         Forget the stored credential for this URL

Options
  --url <url>            the real MCP endpoint, e.g. https://host/mcp         (required)
  --client-id <id>       skip dynamic registration and use this client id
  --port <n>             loopback port for the gateway            (default 33419)
  --redirect-host <h>    host used inside the OAuth redirect URI  (default localhost)
  --scope <list>         space or comma separated scopes          (default openid,email,profile)
  --auth-server <url>    issuer override when the server has no RFC 9728 challenge
  --store <dir>          state directory  (default ${defaultStoreDir()})
  --device               device flow: no browser, no listener, no redirect (for containers)
  --client-secret <s>    confidential client secret (visible in ps output; prefer the next flag)
  --client-secret-env <VAR>  read the client secret from an environment variable
  --token-auth-method <m>    client_secret_basic (default) or client_secret_post
  --authorize-param k=v  extra authorization-endpoint parameter, repeatable
  --token-param k=v      extra token-endpoint parameter, repeatable
  --server-name <name>   name used in print-config snippets (default: from the URL host)
  --no-open              do not try to open a browser (print the URL instead)
  --quiet                suppress progress output
  -h, --help             this text

Why a gateway: many MCP clients can only send one static Authorization header, so a server
that implements the MCP authorization flow (RFC 9728 + OAuth 2.1 + PKCE) is unreachable from
them. This process performs that flow, keeps the tokens (chmod 600, outside the repo) and
refreshes them silently; the client keeps talking to http://127.0.0.1:<port>/mcp with a
stable local token that is *not* the OAuth credential.
`;

function parseArgs(argv) {
  const out = { _: [], scope: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('-')) {
      out._.push(token);
      continue;
    }
    const [rawKey, inline] = token.replace(/^--?/, '').split(/=(.*)/s);
    const key = rawKey === 'h' ? 'help' : rawKey.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    let value = inline;
    if (value === undefined) {
      const next = argv[index + 1];
      if (next !== undefined && !next.startsWith('-')) value = argv[(index += 1)];
      else value = true;
    }
    if (key === 'scope') out.scope.push(...String(value).split(/[,\s]+/).filter(Boolean));
    else if (key === 'authorizeParam' || key === 'tokenParam') (out[key] ||= []).push(String(value));
    else out[key] = value;
  }
  return out;
}

function required(options, key, hint) {
  const value = options[key];
  if (!value || value === true) throw new Error(`--${key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)} is required${hint ? ` (${hint})` : ''}`);
  return String(value);
}

/** Load the state for a URL, creating an empty one (not yet written) when absent. */
function loadOrInit(options) {
  const url = String(options.url);
  const store = options.store ? String(options.store) : defaultStoreDir();
  const stateFile = store.endsWith('.json') ? store : storeFileFor(url, store);
  const existing = loadState(stateFile);
  const state = existing || { version: 1, mcpUrl: url };
  ensureLocalToken(state);
  if (!existing) saveState(stateFile, state);
  return { url, state, stateFile };
}

function gatewayOptions(options, { state, stateFile, url, log }) {
  return {
    mcpUrl: url,
    state,
    stateFile,
    proxyPort: Number(options.port || 33419),
    redirectHost: String(options.redirectHost || 'localhost'),
    clientId: options.clientId ? String(options.clientId) : undefined,
    clientSecret: resolveClientSecret(options),
    tokenAuthMethod: options.tokenAuthMethod ? String(options.tokenAuthMethod) : undefined,
    authorizeParams: paramPairs(options.authorizeParam, '--authorize-param'),
    tokenParams: paramPairs(options.tokenParam, '--token-param'),
    authorizationServer: options.authServer ? String(options.authServer) : undefined,
    scopes: options.scope.length ? options.scope : undefined,
    log,
  };
}

/**
 * The client secret, preferring an environment variable so it never lands in the shell history
 * or in `ps` output. `--client-secret` exists for one-off use and says so in the usage text.
 */
function resolveClientSecret(options) {
  if (options.clientSecretEnv) {
    const name = String(options.clientSecretEnv);
    const value = process.env[name];
    if (!value) throw new Error(`--client-secret-env ${name}: that variable is unset or empty`);
    return value;
  }
  return options.clientSecret ? String(options.clientSecret) : undefined;
}

/** Turn repeated `k=v` flags into an object, rejecting a malformed pair loudly. */
function paramPairs(values, flag) {
  const out = {};
  for (const raw of values || []) {
    const index = raw.indexOf('=');
    if (index <= 0) throw new Error(`${flag} expects key=value, got "${raw}"`);
    out[raw.slice(0, index)] = raw.slice(index + 1);
  }
  return Object.keys(out).length ? out : undefined;
}

function clientSnippets({ localUrl, localToken, proxyPort, serverName = 'mcp' }) {
  return `Local gateway URL : ${localUrl}
Local gateway token: ${localToken}      <- stable; NOT the OAuth credential

DSH (DeepSeek Harness) — add to %USERPROFILE%\\.dsh\\profiles\\<profile>\\cordis.patch.yml
------------------------------------------------------------------------------
- insert:
    - id: ${serverName}-mcp
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: ${serverName}
        transport: streamable-http
        url: ${localUrl}
        headers:
          x-mcp-gateway-token: '${localToken}'
        failOnStartupError: false

Generic MCP client (Cursor, Windsurf, Claude Desktop, ...)
------------------------------------------------------------------------------
{
  "mcpServers": {
    "${serverName}": {
      "type": "http",
      "url": "${localUrl}",
      "headers": { "x-mcp-gateway-token": "${localToken}" }
    }
  }
}

curl
------------------------------------------------------------------------------
curl -sS -X POST ${localUrl} \\
  -H 'x-mcp-gateway-token: ${localToken}' \\
  -H 'content-type: application/json' \\
  -H 'accept: application/json, text/event-stream' \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

Start it with:  mcp-oauth-gateway serve --url <mcp-url> --port ${proxyPort}
`;
}

async function main(argv) {
  const options = parseArgs(argv);
  const command = options._[0] || (options.help ? 'help' : undefined);

  if (!command || command === 'help' || options.help) {
    process.stdout.write(USAGE);
    return 0;
  }

  const log = options.quiet ? () => {} : (message) => process.stderr.write(`${message}\n`);

  // Validate the repeatable k=v flags for every command, so a typo is a loud error rather than
  // a flag that the command happens to ignore.
  paramPairs(options.authorizeParam, '--authorize-param');
  paramPairs(options.tokenParam, '--token-param');

  switch (command) {
    case 'login': {
      const { url, state, stateFile } = loadOrInit({ ...options, url: required(options, 'url') });
      const description = options.device
        ? await loginWithDeviceCode({ ...gatewayOptions(options, { state, stateFile, url, log }) })
        : await login({
            ...gatewayOptions(options, { state, stateFile, url, log }),
            openBrowser: !options.noOpen,
          });
      process.stdout.write(`${JSON.stringify(description, null, 2)}\n`);
      return 0;
    }

    case 'serve': {
      const { url, state, stateFile } = loadOrInit({ ...options, url: required(options, 'url') });
      const gateway = await createGateway(gatewayOptions(options, { state, stateFile, url, log }));
      process.stdout.write(clientSnippets(gateway));
      log(`gateway listening — state: ${stateFile}`);
      const stop = async () => {
        await gateway.stop();
        process.exit(0);
      };
      process.on('SIGINT', stop);
      process.on('SIGTERM', stop);
      await new Promise(() => {}); // run until interrupted
      return 0;
    }

    case 'status': {
      const { url, state, stateFile } = loadOrInit({ ...options, url: required(options, 'url') });
      process.stdout.write(`${JSON.stringify({ stateFile, ...describeState(state) }, null, 2)}\n`);
      return 0;
    }

    case 'refresh': {
      const { url, state, stateFile } = loadOrInit({ ...options, url: required(options, 'url') });
      const gateway = await createGateway(gatewayOptions(options, { state, stateFile, url, log }));
      try {
        await gateway.refreshNow();
        process.stdout.write(`${JSON.stringify(describeState(state), null, 2)}\n`);
      } finally {
        await gateway.stop();
      }
      return 0;
    }

    case 'print-config': {
      const { url, state } = loadOrInit({ ...options, url: required(options, 'url') });
      const proxyPort = Number(options.port || 33419);
      const serverName = options.serverName ? String(options.serverName) : serverNameFor(url);
      process.stdout.write(
        clientSnippets({
          localUrl: `http://127.0.0.1:${proxyPort}/mcp`,
          localToken: state.localToken,
          proxyPort,
          serverName,
        }),
      );
      return 0;
    }

    case 'logout': {
      const { stateFile } = loadOrInit({ ...options, url: required(options, 'url') });
      fs.rmSync(stateFile, { force: true });
      process.stdout.write(`removed ${stateFile}\n`);
      return 0;
    }

    default:
      process.stderr.write(`unknown command: ${command}\n\n${USAGE}`);
      return 2;
  }
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (error) {
  const message = error instanceof OAuthError ? error.message : `${error.name}: ${error.message}`;
  process.stderr.write(`\n${message}\n`);
  process.exitCode = 1;
}
