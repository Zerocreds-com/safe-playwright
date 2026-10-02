// Security guards for the golden MCP tool set (issue #21).
//
// Every guard here is a fail-closed policy point: the tool boundary is
// where "security + usability" are both decided. Nothing in this module
// ever prints a secret.

import net from 'node:net';

// Hosts that are never reachable, not even via the private-host
// allowlist: cloud instance metadata services.
const ALWAYS_BLOCKED_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  '100.100.100.200', // Alibaba metadata
]);
const ALWAYS_BLOCKED_IPV4 = new Set(['169.254.169.254']); // AWS/GCP/Azure IMDSv4
const ALWAYS_BLOCKED_IPV6 = new Set(['fd00:ec2::254']); // AWS IMDSv6

function normalizeHost(hostname) {
  let host = String(hostname || '').toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  // IPv4-mapped IPv6 (:ffff:a.b.c.d)
  const mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return mapped[1];
  return host;
}

function isPrivateIpv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n))) return false;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true; // link-local (incl. IMDS range)
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast/reserved
  return false;
}

function isPrivateIpv6(ip) {
  if (ip === '::1' || ip === '::') return true;
  if (/^f[cd]/.test(ip)) return true; // ULA
  if (/^fe8[0-9a-f]:/.test(ip)) return true; // link-local
  return false;
}

// Returns { ok: true } or { ok: false, reason } — never throws.
export function checkNavigation(rawUrl, allowPrivateHosts = []) {
  let url;
  try {
    url = new URL(String(rawUrl));
  } catch {
    return { ok: false, reason: 'not a valid URL' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: `scheme "${url.protocol}" is allowed only for http/https` };
  }
  if (url.username || url.password) {
    return { ok: false, reason: 'URLs with embedded credentials (userinfo) are rejected' };
  }

  const host = normalizeHost(url.hostname);
  const allowed = new Set(allowPrivateHosts.map((h) => String(h).toLowerCase()));

  if (ALWAYS_BLOCKED_HOSTS.has(host) || ALWAYS_BLOCKED_IPV4.has(host) || ALWAYS_BLOCKED_IPV6.has(host)) {
    return { ok: false, reason: 'instance metadata endpoints are always blocked' };
  }

  const isIp = net.isIP(host) !== 0;
  const privateTarget = host === 'localhost'
    || (isIp && (isPrivateIpv4(host) || isPrivateIpv6(host)))
    || host.endsWith('.localhost');
  if (privateTarget && !allowed.has(host)) {
    return {
      ok: false,
      reason: `private/loopback host "${host}" requires an explicit allowlist entry (SAFE_MCP_PRIVATE_ALLOW)`,
    };
  }
  return { ok: true };
}

// Canary values registered via SAFE_MCP_CANARY (comma-separated).
// A tool argument that contains one is a hard policy failure (C4-style
// detection of a raw secret crossing the model boundary).
export function findCanary(text, canaryValues) {
  if (typeof text !== 'string' || text.length === 0) return false;
  return canaryValues.some((canary) => canary.length > 0 && text.includes(canary));
}

export function argumentsContainCanary(value, canaryValues) {
  if (typeof value === 'string') return findCanary(value, canaryValues);
  if (Array.isArray(value)) return value.some((item) => argumentsContainCanary(item, canaryValues));
  if (value && typeof value === 'object') {
    return Object.values(value).some((item) => argumentsContainCanary(item, canaryValues));
  }
  return false;
}

export class PolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyError';
    this.policy = true;
  }
}

// In-page collector for browser_snapshot. Runs via page.evaluate:
// builds a ref-tagged tree, and applies the value policy:
//   * password field holding a value  -> flag (caller refuses everything);
//   * password / tel / OTP / card values are never serialized;
//   * ordinary text field values are returned (usability).
export function collectSnapshot() {
  const interestingTags = new Set([
    'a', 'button', 'input', 'textarea', 'select', 'label', 'img',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'li', 'summary', 'option', 'th', 'td',
  ]);

  const isVisible = (el) => {
    const rects = el.getClientRects();
    if (rects.length === 0) return false;
    const style = window.getComputedStyle(el);
    return style.visibility !== 'hidden' && style.display !== 'none';
  };

  const cssPath = (el) => {
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && node !== document.documentElement) {
      const tag = node.tagName.toLowerCase();
      const parent = node.parentElement;
      if (!parent) break;
      const sameTag = Array.from(parent.children).filter((c) => c.tagName === node.tagName);
      parts.unshift(sameTag.length > 1 ? `${tag}:nth-of-type(${sameTag.indexOf(node) + 1})` : tag);
      node = parent;
    }
    return `html>${parts.join('>')}`;
  };

  const labelFor = (el) => {
    if (el.getAttribute('aria-label')) return el.getAttribute('aria-label');
    if (el.labels && el.labels.length > 0) return el.labels[0].textContent.trim();
    const wrapped = el.closest('label');
    if (wrapped) return wrapped.textContent.trim();
    return null;
  };

  const valuePolicy = (el) => {
    const type = (el.getAttribute('type') || 'text').toLowerCase();
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
    if (type === 'password') return 'never';
    if (type === 'tel') return 'never';
    if (ac.includes('one-time-code')) return 'never';
    if (ac.includes('cc-')) return 'never';
    return 'show';
  };

  const nodes = [];
  let passwordWithValue = false;
  let counter = 0;

  const textCarriers = new Set(['div', 'span', 'section', 'article', 'main', 'form']);
  for (const el of document.querySelectorAll('*')) {
    const tag = el.tagName.toLowerCase();
    const roleAttr = el.getAttribute('role');
    const hasOwnText = Array.from(el.childNodes).some(
      (node) => node.nodeType === 3 && node.textContent.trim().length > 0,
    );
    if (!interestingTags.has(tag) && !roleAttr && !(textCarriers.has(tag) && hasOwnText)) continue;
    if (!isVisible(el)) continue;

    const type = (el.getAttribute('type') || '').toLowerCase();
    let role = roleAttr || null;

    if (tag === 'a') role = role || 'link';
    else if (tag === 'button') role = role || 'button';
    else if (tag === 'input') {
      if (type === 'checkbox') role = role || 'checkbox';
      else if (type === 'radio') role = role || 'radio';
      else if (type === 'submit' || type === 'button' || type === 'reset') role = role || 'button';
      else if (type === 'password') role = role || 'password';
      else role = role || 'textbox';
    } else if (tag === 'textarea' || tag === 'select') role = role || roleAttr || (tag === 'select' ? 'combobox' : 'textbox');
    else if (/^h[1-6]$/.test(tag)) role = role || 'heading';
    else if (tag === 'img') role = role || 'image';
    else if (!role) {
      // plain text carriers
      role = 'text';
    }

    let name = el.getAttribute('aria-label')
      || (typeof labelFor(el) === 'string' ? labelFor(el) : null)
      || el.getAttribute('alt')
      || el.getAttribute('placeholder')
      || '';
    if (!name && (role === 'text' || role === 'heading' || role === 'link' || role === 'button')) {
      name = (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 120);
    }
    if (!name && (tag === 'input' || tag === 'textarea')) {
      name = el.getAttribute('name') || el.id || type || tag;
    }
    if (!name) continue;

    const entry = { ref: `r${counter++}`, role, path: cssPath(el) };
    entry.name = String(name).slice(0, 200);

    if (tag === 'input' || tag === 'textarea') {
      if (type === 'password') {
        if (el.value !== '') passwordWithValue = true;
        entry.value = '[hidden]';
      } else if (type === 'checkbox' || type === 'radio') {
        entry.checked = Boolean(el.checked);
      } else if (valuePolicy(el) === 'never') {
        entry.value = el.value === '' ? '' : '[hidden]';
      } else {
        entry.value = String(el.value).slice(0, 200);
      }
      if (el.disabled) entry.disabled = true;
    }
    if (tag === 'select') {
      entry.value = String(el.value).slice(0, 100);
    }
    if (tag === 'a' && el.getAttribute('href')) {
      entry.href = String(el.getAttribute('href')).slice(0, 200);
    }
    nodes.push(entry);
  }

  return { nodes, passwordWithValue };
}

// In-page predicate for browser_screenshot: is this a credential page?
export function credentialPageProbe() {
  const hasPassword = Boolean(document.querySelector('input[type="password"]'));
  const otpWithValue = Array.from(
    document.querySelectorAll('input[autocomplete*="one-time-code"]'),
  ).some((el) => el.value !== '');
  const cardWithValue = Array.from(
    document.querySelectorAll('input[autocomplete*="cc-"]'),
  ).some((el) => el.value !== '');
  return { hasPassword, otpWithValue, cardWithValue };
}
