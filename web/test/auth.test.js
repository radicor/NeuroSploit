'use strict';
// SEC-005 — the console must gate every /api/* route in `token` mode and must not
// gate anything in `none` mode (the bridge default). These tests bind a real
// server and drive it over HTTP: no handler is re-implemented.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { startServer, authMode, metaPayload } = require('../server.js');

const ROOT = path.resolve(__dirname, '..', '..');
const TOKEN_FILE = path.join(ROOT, '.neurosploit', 'console-token');

function readToken() { return fs.readFileSync(TOKEN_FILE, 'utf8').trim(); }
function setMode(m) {
  if (m === undefined) delete process.env.NEUROSPLOIT_WEB_AUTH;
  else process.env.NEUROSPLOIT_WEB_AUTH = m;
}
function sessionCookie(res) {
  const raw = res.headers.get('set-cookie') || '';
  const m = /ns_session=([^;]+)/.exec(raw);
  return m ? m[0] : null;
}
async function login(srv, token) {
  const res = await fetch(`${srv.url}/api/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  });
  return res;
}

test('none mode leaves the console open (c1 / TN-1)', async () => {
  setMode(undefined);
  const srv = await startServer({ port: 0 });
  try {
    const res = await fetch(`${srv.url}/api/meta`);
    assert.strictEqual(res.status, 200, 'the bridge default must not break the console');
    assert.strictEqual(authMode(), 'none');
  } finally { await srv.close(); setMode(undefined); }
});

test('none mode warns loudly on start (c2)', async () => {
  setMode(undefined);
  const lines = [];
  const orig = console.log;
  console.log = (...a) => { lines.push(a.join(' ')); };
  let srv;
  try { srv = await startServer({ port: 0 }); } finally { console.log = orig; }
  try {
    assert.match(lines.join('\n'), /WARNING: console authentication is disabled/);
  } finally { await srv.close(); setMode(undefined); }
});

test('token mode refuses every /api/* route without a credential (c3 / TN-2)', async () => {
  setMode('token');
  const srv = await startServer({ port: 0 });
  try {
    const cases = [
      ['GET', '/api/meta'], ['GET', '/api/runs'], ['GET', '/api/agents'],
      ['POST', '/api/exploit'], ['DELETE', '/api/runs'],
    ];
    for (const [method, p] of cases) {
      const res = await fetch(`${srv.url}${p}`, {
        method, headers: { 'Content-Type': 'application/json' }, body: method === 'GET' ? undefined : '{}',
      });
      assert.strictEqual(res.status, 401, `${method} ${p} must be 401 without a credential`);
    }
  } finally { await srv.close(); setMode(undefined); }
});

test('the two auth endpoints stay reachable (c4 / TN-3)', async () => {
  setMode('token');
  const srv = await startServer({ port: 0 });
  try {
    const st = await fetch(`${srv.url}/api/auth/status`);
    assert.strictEqual(st.status, 200);
    const body = await st.json();
    assert.strictEqual(body.auth, 'token');
    assert.strictEqual(body.authenticated, false);

    // login must answer 401 (not 404/405) so a wrong token is distinguishable
    const bad = await login(srv, 'nope');
    assert.strictEqual(bad.status, 401, 'login must be reachable unauthenticated');
  } finally { await srv.close(); setMode(undefined); }
});

test('login issues a working HttpOnly session (c5 / TN-2)', async () => {
  setMode('token');
  const srv = await startServer({ port: 0 });
  try {
    const res = await login(srv, readToken());
    assert.strictEqual(res.status, 200);
    const raw = res.headers.get('set-cookie') || '';
    assert.match(raw, /HttpOnly/);
    assert.match(raw, /SameSite=Strict/);
    assert.match(raw, /Path=\//);

    const cookie = sessionCookie(res);
    assert.ok(cookie, 'a session cookie must be set');
    const ok = await fetch(`${srv.url}/api/meta`, { headers: { cookie } });
    assert.strictEqual(ok.status, 200, 'the freshly issued cookie must authenticate');
  } finally { await srv.close(); setMode(undefined); }
});

test('a wrong or truncated token is 401, never 500 (c6, c7 / TN-4, TN-7)', async () => {
  setMode('token');
  const srv = await startServer({ port: 0 });
  try {
    const tok = readToken();
    assert.strictEqual((await login(srv, 'wrong')).status, 401);
    // prefix of the real token must not pass
    assert.strictEqual((await login(srv, tok.slice(0, tok.length - 1))).status, 401);
    // a much shorter value must be a 401, not the timingSafeEqual length throw
    assert.strictEqual((await login(srv, 'x')).status, 401);
  } finally { await srv.close(); setMode(undefined); }
});

test('a session survives a restart; a forged one does not (c8, c9 / TN-5)', async () => {
  setMode('token');
  let srv = await startServer({ port: 0 });
  let cookie;
  try {
    const res = await login(srv, readToken());
    cookie = sessionCookie(res);
    assert.ok(cookie);
  } finally {
    const port = srv.port;
    await srv.close();
    srv = await startServer({ port: 0 });
    try {
      const ok = await fetch(`${srv.url}/api/meta`, { headers: { cookie } });
      assert.strictEqual(ok.status, 200, 'a persisted session must survive a restart');
      void port;

      const forged = await fetch(`${srv.url}/api/meta`, { headers: { cookie: 'ns_session=forged-value' } });
      assert.strictEqual(forged.status, 401, 'an id whose hash is unknown must be refused');
    } finally { await srv.close(); setMode(undefined); }
  }
});

test('Bearer works for scripts, and a wrong Bearer does not (c10 / TN-9)', async () => {
  setMode('token');
  const srv = await startServer({ port: 0 });
  try {
    const tok = readToken();
    const ok = await fetch(`${srv.url}/api/meta`, { headers: { authorization: `Bearer ${tok}` } });
    assert.strictEqual(ok.status, 200);
    const bad = await fetch(`${srv.url}/api/meta`, { headers: { authorization: 'Bearer wrong' } });
    assert.strictEqual(bad.status, 401);
  } finally { await srv.close(); setMode(undefined); }
});

test('rotate kills the old token, keeps sessions, and revokeSessions drops them (c11 / TN-6)', async () => {
  setMode('token');
  const srv = await startServer({ port: 0 });
  try {
    const oldTok = readToken();
    const res = await login(srv, oldTok);
    const cookie = sessionCookie(res);
    assert.ok(cookie);

    const rot = await fetch(`${srv.url}/api/auth/rotate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', authorization: `Bearer ${oldTok}` }, body: '{}',
    });
    assert.strictEqual(rot.status, 200);

    const newTok = readToken();
    assert.notStrictEqual(newTok, oldTok, 'rotate must mint a new token');

    assert.strictEqual((await login(srv, oldTok)).status, 401, 'the old token must die');
    assert.strictEqual((await login(srv, newTok)).status, 200, 'the new token must work');

    const stillIn = await fetch(`${srv.url}/api/meta`, { headers: { cookie } });
    assert.strictEqual(stillIn.status, 200, 'sessions survive rotation by default');

    const rev = await fetch(`${srv.url}/api/auth/rotate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', authorization: `Bearer ${newTok}` },
      body: JSON.stringify({ revokeSessions: true }),
    });
    assert.strictEqual(rev.status, 200);
    const dropped = await fetch(`${srv.url}/api/meta`, { headers: { cookie } });
    assert.strictEqual(dropped.status, 401, 'revokeSessions must drop existing sessions');
  } finally { await srv.close(); setMode(undefined); }
});

test('the root token never appears in a response body, and the file is 0600 (c12, c13 / TN-8)', async () => {
  setMode('token');
  const srv = await startServer({ port: 0 });
  try {
    const tok = readToken();
    const auth = { authorization: `Bearer ${tok}` };
    for (const p of ['/api/meta', '/api/auth/status', '/api/runs', '/api/agents']) {
      const res = await fetch(`${srv.url}${p}`, { headers: auth });
      const text = await res.text();
      assert.ok(!text.includes(tok), `${p} leaked the root token`);
    }
    const mode = fs.statSync(TOKEN_FILE).mode & 0o777;
    assert.strictEqual(mode, 0o600, `token file mode ${mode.toString(8)} must be 600`);
  } finally { await srv.close(); setMode(undefined); }
});

test('the SSE route is authenticated, not blocked (c14 / TN-10)', async () => {
  setMode('token');
  const srv = await startServer({ port: 0 });
  try {
    const res = await login(srv, readToken());
    const cookie = sessionCookie(res);

    // unauthenticated: the gate refuses before the stream opens
    const noAuth = await fetch(`${srv.url}/api/exploit/does-not-exist/events`);
    assert.strictEqual(noAuth.status, 401);

    // authenticated: the request reaches the route (whatever it then answers),
    // which is the property that matters — the cookie must travel on EventSource.
    const withAuth = await fetch(`${srv.url}/api/exploit/does-not-exist/events`, { headers: { cookie } });
    assert.notStrictEqual(withAuth.status, 401, 'a session cookie must not be refused at the gate');
    if (withAuth.body) await withAuth.body.cancel().catch(() => {});
  } finally { await srv.close(); setMode(undefined); }
});

test('owed c15: /api/meta hides paths from a remote peer, over HTTP and at the handler', async () => {
  setMode(undefined);
  const srv = await startServer({ port: 0 });
  try {
    const res = await fetch(`${srv.url}/api/meta`);
    const body = await res.json();
    assert.deepStrictEqual(Object.keys(body).sort(), ['binary', 'root', 'version'],
      'a loopback peer may see paths');

    // a remote peer cannot be produced over a loopback socket, so the policy is
    // asserted through the exported handler the route calls
    const remote = metaPayload('203.0.113.9');
    assert.deepStrictEqual(Object.keys(remote), ['version'],
      'a remote peer must not learn the filesystem layout');
  } finally { await srv.close(); setMode(undefined); }
});

test('owed c16: the validation 400 reaches the client over HTTP', async () => {
  setMode(undefined);
  const srv = await startServer({ port: 0 });
  try {
    const bad = await fetch(`${srv.url}/api/exploit`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'mcp', target: 'http://example.com' }),
    });
    assert.strictEqual(bad.status, 400, 'an unsupported mode must be a client error');
    const body = await bad.json();
    assert.strictEqual(body.field, 'mode', `the field must be named: ${JSON.stringify(body)}`);

    const flag = await fetch(`${srv.url}/api/exploit`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'run', target: '--offline' }),
    });
    assert.strictEqual(flag.status, 400);
    assert.strictEqual((await flag.json()).field, 'target');
  } finally { await srv.close(); setMode(undefined); }
});
