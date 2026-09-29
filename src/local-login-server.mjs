// Local test login server — the only login target for the P4 PoC.
//
// Deliberately a loopback HTTP server: the PoC never touches a real site.
// It models the minimum real-world shape: a login form (username +
// password), a session cookie issued on success, and an authenticated
// page that requires the cookie. The password is never echoed back in any
// response body.

import crypto from 'node:crypto';
import http from 'node:http';

const LOGIN_PAGE = (error = '') => `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Local test login</title></head>
<body>
  <h1>Local test login</h1>
  ${error ? `<p id="error">${error}</p>` : ''}
  <form id="login-form" method="post" action="/login">
    <label>Username <input id="username" name="username" type="text" autocomplete="username"></label>
    <label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>`;

const DASHBOARD_PAGE = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Dashboard</title></head>
<body>
  <h1>Dashboard</h1>
  <div id="auth-state" data-authenticated="true">Welcome, demo-user — you are signed in.</div>
  <a id="logout" href="/login">Back to login</a>
</body>
</html>`;

const FORM_DEMO_PAGE = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Form demo</title></head>
<body>
  <h1>Form demo</h1>
  <form>
    <label>Note <input id="note" name="note" type="text" value="meet at noon"></label>
    <label>Phone <input id="phone" name="phone" type="tel" autocomplete="tel" value="555-0142"></label>
    <label>Code <input id="otp" name="otp" type="text" autocomplete="one-time-code" value="493812"></label>
    <label>Card <input id="card" name="card" type="text" autocomplete="cc-number" value="4111111111111111"></label>
    <button type="button">Save</button>
  </form>
</body>
</html>`;

// A page where a password field still holds a value: the fixture for
// snapshot fail-closed and screenshot-refusal tests.
const PREFILLED_PAGE = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Re-authenticate</title></head>
<body>
  <h1>Re-authenticate</h1>
  <form>
    <label>Password <input id="password" name="password" type="password" value="lingering-secret-1"></label>
    <button type="submit">Continue</button>
  </form>
</body>
</html>`;

const FORBIDDEN_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in required</title></head>
<body><div id="auth-state" data-authenticated="false">Sign in required.</div></body></html>`;

function timingSafeEquals(a, b) {
  const bufferA = Buffer.from(String(a));
  const bufferB = Buffer.from(String(b));
  if (bufferA.length !== bufferB.length) return false;
  return crypto.timingSafeEqual(bufferA, bufferB);
}

function sendHtml(res, status, html, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...headers });
  res.end(html);
}

export async function startLocalLoginServer({ username, password, host = '127.0.0.1' }) {
  const sessions = new Map();
  const stats = { acceptedLogins: 0, rejectedLogins: 0, dashboardViews: 0, loginPageViews: 0 };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://${host}`);

    if (req.method === 'GET' && url.pathname === '/login') {
      stats.loginPageViews += 1;
      sendHtml(res, 200, LOGIN_PAGE());
      return;
    }

    if (req.method === 'POST' && url.pathname === '/login') {
      const chunks = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => {
        const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
        const candidateUser = form.get('username') ?? '';
        const candidatePassword = form.get('password') ?? '';
        const ok =
          timingSafeEquals(candidateUser, username) &&
          timingSafeEquals(candidatePassword, password);
        if (!ok) {
          stats.rejectedLogins += 1;
          sendHtml(res, 401, LOGIN_PAGE('Invalid credentials.'));
          return;
        }
        stats.acceptedLogins += 1;
        const sessionId = crypto.randomBytes(32).toString('hex');
        sessions.set(sessionId, { username, createdAt: Date.now() });
        sendHtml(res, 302, 'Redirecting to dashboard.', {
          Location: '/dashboard',
          'Set-Cookie': `session=${sessionId}; HttpOnly; Path=/; SameSite=Strict`,
        });
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/dashboard') {
      const sessionId = (req.headers.cookie ?? '')
        .split(';')
        .map((part) => part.trim())
        .find((part) => part.startsWith('session='))?.slice('session='.length);
      if (!sessionId || !sessions.has(sessionId)) {
        sendHtml(res, 302, 'Redirecting to login.', { Location: '/login' });
        return;
      }
      stats.dashboardViews += 1;
      sendHtml(res, 200, DASHBOARD_PAGE);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/form-demo') {
      sendHtml(res, 200, FORM_DEMO_PAGE);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/prefilled') {
      sendHtml(res, 200, PREFILLED_PAGE);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/whoami') {
      const sessionId = (req.headers.cookie ?? '')
        .split(';')
        .map((part) => part.trim())
        .find((part) => part.startsWith('session='))?.slice('session='.length);
      const session = sessionId ? sessions.get(sessionId) : undefined;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ authenticated: Boolean(session), username: session?.username ?? null }));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(stats));
      return;
    }

    sendHtml(res, 404, FORBIDDEN_PAGE.replace('Sign in required.', 'Not found.'));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, host, resolve);
  });

  const { port } = server.address();
  return {
    url: `http://${host}:${port}`,
    port,
    stats,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
