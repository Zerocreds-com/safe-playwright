// The golden MCP tool set (issue #21): seven tools, each with its
// security policy attached. What is NOT here is as deliberate as what
// is: no evaluate/run-code, no cookie access, no console dumps, no CDP
// attachment, no environment access (checklist §6.2).

import { PolicyError, argumentsContainCanary } from './guards.mjs';
import { performLogin } from './login.mjs';

const asJson = (value) => JSON.stringify(value);

export const GOLDEN_TOOLS = [
  {
    name: 'browser_navigate',
    description:
      'Open a URL in the browser. Only http/https; instance-metadata hosts are always '
      + 'blocked; private/loopback hosts require an explicit allowlist on the server.',
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string', description: 'Absolute http(s) URL' } },
      required: ['url'],
      additionalProperties: false,
    },
    handler: async ({ session, allowPrivateHosts }, args) => {
      const result = await session.navigate(args.url, allowPrivateHosts);
      return { kind: 'text', text: asJson(result) };
    },
  },
  {
    name: 'browser_snapshot',
    description:
      'Read the current page as a ref-tagged accessibility-style tree (text only, no '
      + 'pixels). Field values for password/OTP/tel/card inputs are never included, and '
      + 'the call fails if a password field holds a value. Use the refs with '
      + 'browser_click / browser_type / browser_wait.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    handler: async ({ session }) => ({ kind: 'text', text: await session.snapshot() }),
  },
  {
    name: 'browser_click',
    description: 'Click the element identified by a ref from the latest browser_snapshot.',
    inputSchema: {
      type: 'object',
      properties: { ref: { type: 'string', description: 'Reference like r12' } },
      required: ['ref'],
      additionalProperties: false,
    },
    handler: async ({ session }, args) => ({
      kind: 'text',
      text: asJson(await session.click(args.ref)),
    }),
  },
  {
    name: 'browser_type',
    description:
      'Fill an input with plain text and optionally submit. Refuses password/OTP fields '
      + '(secrets never enter the agent browser — use browser_login) and rejects values '
      + 'that match a registered canary.',
    inputSchema: {
      type: 'object',
      properties: {
        ref: { type: 'string' },
        text: { type: 'string' },
        submit: { type: 'boolean', default: false },
      },
      required: ['ref', 'text'],
      additionalProperties: false,
    },
    handler: async ({ session }, args) => {
      const result = await session.type(args.ref, args.text);
      if (args.submit) {
        await session.locatorFor(args.ref).press('Enter');
        result.submitted = true;
        result.url = session.page.url();
      }
      return { kind: 'text', text: asJson(result) };
    },
  },
  {
    name: 'browser_wait',
    description: 'Wait for a bounded time (0-10s) or for a ref to become visible/hidden.',
    inputSchema: {
      type: 'object',
      properties: {
        timeMs: { type: 'number', description: 'Milliseconds (max 10000)' },
        ref: { type: 'string' },
        state: { type: 'string', enum: ['visible', 'hidden'] },
      },
      additionalProperties: false,
    },
    handler: async ({ session }, args) => ({
      kind: 'text',
      text: asJson(await session.wait(args)),
    }),
  },
  {
    name: 'browser_login',
    description:
      'Log in via the audited fill browser (P5): the credential named by the cred:// '
      + 'reference is filled in a separate sealed process; only the resulting session '
      + 'cookies are handed to this browser. The password never enters this tool call.',
    inputSchema: {
      type: 'object',
      properties: {
        credentialRef: {
          type: 'string',
          pattern: '^cred://',
          description: 'Credential reference, e.g. cred://service/login',
        },
      },
      required: ['credentialRef'],
      additionalProperties: false,
    },
    handler: async ({ session, store, canaryValues }, args) => {
      await session.start();
      const result = await performLogin(args.credentialRef, session.context, store, canaryValues);
      return { kind: 'text', text: asJson(result) };
    },
  },
  {
    name: 'browser_screenshot',
    description:
      'Capture the visible page as PNG. Refused on credential pages (any password field '
      + 'or a credential origin) — pixel policy U7.',
    inputSchema: {
      type: 'object',
      properties: { fullPage: { type: 'boolean', default: false } },
      additionalProperties: false,
    },
    handler: async ({ session }, args) => {
      const shot = await session.screenshot({ fullPage: Boolean(args.fullPage) });
      return { kind: 'image', mimeType: shot.mime, data: shot.data };
    },
  },
];

export function listGoldenTools() {
  return GOLDEN_TOOLS.map(({ name, description, inputSchema }) => ({
    name,
    description,
    inputSchema,
  }));
}

export async function callGoldenTool(name, args, context) {
  const tool = GOLDEN_TOOLS.find((entry) => entry.name === name);
  if (!tool) {
    return { error: `unknown tool: ${name}` };
  }
  if (argumentsContainCanary(args, context.canaryValues ?? [])) {
    throw new PolicyError(
      'value matches a registered canary credential — a raw secret crossed the '
        + 'model boundary (C4), refused',
    );
  }
  return tool.handler(context, args ?? {});
}
