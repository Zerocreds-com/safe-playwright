#!/usr/bin/env node
// Golden MCP server (issue #21): stdio, newline-delimited JSON-RPC 2.0,
// zero new dependencies. One sealed browser per server process over the
// Playwright default pipe.
//
// Environment:
//   SAFE_MCP_CRED_STORE   path to a 0600 JSON store: { "cred://ref":
//                          { loginUrl, credFile, authUrl? } }
//   SAFE_MCP_PRIVATE_ALLOW  comma-separated hosts allowed to be
//                          private/loopback (default: none)
//   SAFE_MCP_CANARY       comma-separated canary values; any tool
//                          argument containing one is a hard failure
//
// Run: npm run mcp   (an MCP client speaks JSON-RPC over stdio)

import process from 'node:process';

import { BrowserSession } from './session.mjs';
import { PolicyError } from './guards.mjs';
import { loadCredentialStore } from './login.mjs';
import { callGoldenTool, listGoldenTools } from './tools.mjs';

const SERVER_INFO = { name: 'safe-playwright-mcp', version: '0.1.0' };
const SUPPORTED_PROTOCOL = '2025-06-18';

const parseList = (value) =>
  String(value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

const context = {
  session: new BrowserSession(),
  store: loadCredentialStore(),
  allowPrivateHosts: parseList(process.env.SAFE_MCP_PRIVATE_ALLOW),
  canaryValues: parseList(process.env.SAFE_MCP_CANARY),
};
function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function reply(id, result) {
  send({ jsonrpc: '2.0', id, result });
}

function replyError(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}

async function handle(message) {
  const { id, method, params } = message;
  const isNotification = id === undefined || id === null;

  switch (method) {
    case 'initialize':
      return reply(id, {
        protocolVersion:
          typeof params?.protocolVersion === 'string' ? params.protocolVersion : SUPPORTED_PROTOCOL,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      });
    case 'ping':
      return reply(id, {});
    case 'tools/list':
      return reply(id, { tools: listGoldenTools() });
    case 'tools/call': {
      const name = params?.name;
      const args = params?.arguments ?? {};
      try {
        const result = await callGoldenTool(name, args, context);
        if (result.error) {
          return reply(id, {
            content: [{ type: 'text', text: result.error }],
            isError: true,
          });
        }
        if (result.kind === 'image') {
          return reply(id, {
            content: [{ type: 'image', data: result.data, mimeType: result.mimeType }],
          });
        }
        return reply(id, { content: [{ type: 'text', text: result.text }] });
      } catch (error) {
        if (error instanceof PolicyError || error?.name === 'PolicyError') {
          // Tool-level failure: MCP convention is isError in the result.
          return reply(id, { content: [{ type: 'text', text: error.message }], isError: true });
        }
        // Unexpected failure: report as tool error too, message sanitized
        // to the error text only (no stack, no secrets).
        const text = error?.message ? String(error.message).slice(0, 500) : 'internal error';
        process.stderr.write(`tool ${name} failed: ${text}\n`);
        return reply(id, { content: [{ type: 'text', text: `tool failed: ${text}` }], isError: true });
      }
    }
    default:
      if (isNotification) return undefined; // ignore notifications (initialized, cancelled, ...)
      return replyError(id, -32601, `method not found: ${method}`);
  }
}

let buffer = '';
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (line.length === 0) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      replyError(null, -32700, 'parse error');
      continue;
    }
    handle(message).catch((error) => {
      replyError(message?.id ?? null, -32603, `internal error: ${String(error?.message).slice(0, 200)}`);
    });
  }
});

async function shutdown() {
  await context.session.close();
  process.exit(0);
}

process.stdin.on('end', shutdown);
process.stdin.on('close', shutdown);
process.stdin.on('error', () => shutdown());
