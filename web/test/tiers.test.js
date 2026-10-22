'use strict';
// SEC-007b — tiers, secret redaction, destructive confirms, and the obligations
// earlier verdicts parked here. These drive the exported production functions and
// a real bound server.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const {
  startServer, tierFor, redactSecret, redactEntry, isMasked, unmaskOnWrite,
  requireConfirm, validateIntegration, writeConfig, readConfig,
} = require('../server.js');

const ROOT = path.resolve(__dirname, '..', '..');
const SESSIONS = path.join(ROOT, '.neurosploit', 'console-sessions.json');
const TOKEN_FILE = path.join(ROOT, '.neurosploit', 'console-token');

function setMode(m) {
  if (m === undefined) delete process.env.NEUROSPLOIT_WEB_AUTH;
  else process.env.NEUROSPLOIT_WEB_AUTH = m;
}
function readToken() { return fs.readFileSync(TOKEN_FILE, 'utf8').trim(); }

test('the R set is reads only, mutating routes are W, destructive are D (c1, c4 / TN-1)', () => {
  // reads
  for (const p of ['/api/meta', '/api/runs', '/api/agents', '/api/config/integrations', '/api/auth/status']) {
    assert.strictEqual(tierFor('GET', p), 'R', `${p} must be R`);
  }
  // writes
  for (const [m, p] of [
    ['POST', '/api/exploit'], ['POST', '/api/exploit/abc/input'], ['POST', '/api/repl/abc/input'],
    ['POST', '/api/leads/generate'], ['PUT', '/api/config/repos'], ['POST', '/api/config/repos'],
  ]) {
    assert.strictEqual(tierFor(m, p), 'W', `${m} ${p} must be W`);
  }
  // destructive
  for (const [m, p] of [['DELETE', '/api/runs'], ['DELETE', '/api/runs/ns-1'], ['POST', '/api/auth/rotate']]) {
    assert.strictEqual(tierFor(m, p), 'D', `${m} ${p} must be D`);
  }
  // an unregistered mutating route fails closed at W, never R
  assert.strictEqual(tierFor('POST', '/api/brand-new'), 'W');
  assert.strictEqual(tierFor('GET', '/api/brand-new'), 'R');
});

test('the confirmation phrase must match exactly (c3 / TN-6)', () => {
  assert.strictEqual(requireConfirm({ confirm: 'DELETE ALL' }, 'DELETE ALL').ok, true);
  assert.strictEqual(requireConfirm({ confirm: '  DELETE ALL  ' }, 'DELETE ALL').ok, true, 'edge trim is allowed');
  for (const bad of [{}, { confirm: 'delete all' }, { confirm: 'DELETE  ALL' },
    { confirm: 'DELETE ALL!' }, { confirm: '' }, { confirm: 1 }]) {
    assert.strictEqual(requireConfirm(bad, 'DELETE ALL').ok, false, `${JSON.stringify(bad)} must be refused`);
  }
});

test('bulk delete without the phrase is refused and deletes nothing (c2)', async () => {
  const runId = `ns-test-tiers-${process.pid}`;
  const dir = path.join(ROOT, 'runs', runId);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'meta.json'), '{"target":"example.com"}');
  const srv = await startServer({ port: 0 });
  try {
    const res = await fetch(`${srv.url}/api/runs`, {
      method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: '{}',
    });
    assert.strictEqual(res.status, 400, 'a destructive route must demand the phrase');
    const body = await res.json();
    assert.strictEqual(body.field, 'confirm');
    assert.ok(fs.existsSync(dir), 'nothing may be deleted without the phrase');
  } finally {
    await srv.close();
    fs.rmSync(dir, { recursive: true, force: true });
    setMode(undefined);
  }
});

test('secret values are masked with a four-character preview (c5, c6 / TN-3, TN-5)', () => {
  const secret = 'glpat-abcdefgh1234';
  const masked = redactSecret(secret);
  assert.strictEqual(masked.__masked__, true);
  assert.strictEqual(masked.preview, '…1234');
  assert.ok(!JSON.stringify(masked).includes('abcdefgh'), 'the body of the secret must not survive');
  assert.strictEqual(redactSecret('short').preview, '…5', 'a short secret shows only its length');

  const entry = redactEntry({ name: 'prod', url: 'https://git.example', token: secret, enabled: true }, ['token']);
  assert.strictEqual(entry.name, 'prod');
  assert.strictEqual(entry.url, 'https://git.example');
  assert.strictEqual(entry.enabled, true);
  assert.strictEqual(entry.token.__masked__, true);

  assert.strictEqual(isMasked({ __masked__: true, preview: '…1234' }), true);
  assert.strictEqual(isMasked(secret), false, 'a plain string is not a sentinel');
  assert.strictEqual(isMasked({ __masked__: true }), false, 'the sentinel needs a preview');
});

test('a masked PUT keeps the stored credential (c7 / TN-2)', () => {
  const stored = { token: 'glpat-real-secret-9999' };
  const incoming = { token: redactSecret(stored.token), url: 'https://git.example' };
  const out = unmaskOnWrite(incoming, stored);
  assert.strictEqual(out.token, 'glpat-real-secret-9999', 'the sentinel must resolve to the stored value');
  assert.strictEqual(out.url, 'https://git.example', 'other fields pass through');

  // a genuinely new value replaces the stored one
  const replaced = unmaskOnWrite({ token: 'brand-new-token' }, stored);
  assert.strictEqual(replaced.token, 'brand-new-token');
});

test('integration reads are masked and reveal needs the root token (c5, c8 / TN-4)', async () => {
  const secret = `glpat-${process.pid}-abcd`;
  await writeConfig('integrations', [{
    id: 'gitlab', enabled: true, config: { url: 'https://gitlab.com', token: secret, name: 'prod' },
  }]);
  setMode(undefined);
  const srv = await startServer({ port: 0 });
  try {
    const masked = await (await fetch(`${srv.url}/api/config/integrations`)).json();
    assert.ok(!JSON.stringify(masked).includes(secret), 'the raw token must not appear');
    const entry = masked.find((e) => e.id === 'gitlab');
    assert.strictEqual(entry.config.token.__masked__, true);
    assert.strictEqual(entry.config.name, 'prod', 'non-secret fields must survive');

    const denied = await fetch(`${srv.url}/api/config/integrations?reveal=1`);
    assert.strictEqual(denied.status, 403, 'reveal needs the root token');

    const tok = readToken();
    const revealed = await fetch(`${srv.url}/api/config/integrations?reveal=1`, {
      headers: { authorization: `Bearer ${tok}` },
    });
    assert.strictEqual(revealed.status, 200);
    const raw = await revealed.json();
    assert.strictEqual(raw.find((e) => e.id === 'gitlab').config.token, secret);
  } finally {
    await srv.close();
    await writeConfig('integrations', []);
    setMode(undefined);
  }
});

test('the masked round-trip through HTTP preserves the stored secret (c7)', async () => {
  const secret = `glpat-rt-${process.pid}`;
  await writeConfig('integrations', [{
    id: 'gitlab', enabled: true, config: { url: 'https://gitlab.com', token: secret },
  }]);
  const srv = await startServer({ port: 0 });
  try {
    const masked = await (await fetch(`${srv.url}/api/config/integrations`)).json();
    const entry = masked.find((e) => e.id === 'gitlab');
    // PUT the masked entry straight back, as the UI would
    await fetch(`${srv.url}/api/config/integrations/gitlab`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: entry.enabled, config: entry.config }),
    });
    const stored = await readConfig('integrations');
    assert.strictEqual(stored.find((e) => e.id === 'gitlab').config.token, secret,
      'the sentinel must not be persisted over the credential');
  } finally {
    await srv.close();
    await writeConfig('integrations', []);
    setMode(undefined);
  }
});

test('the sessions file stores hashes only (c9)', async () => {
  setMode('token');
  const srv = await startServer({ port: 0 });
  try {
    const res = await fetch(`${srv.url}/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: readToken() }),
    });
    assert.strictEqual(res.status, 200);
    const id = /ns_session=([^;]+)/.exec(res.headers.get('set-cookie'))[1];

    const raw = fs.readFileSync(SESSIONS, 'utf8');
    assert.ok(!raw.includes(id), 'the raw session id must not be on disk');
    const list = JSON.parse(raw);
    const hit = list.find((e) => e && e.h);
    assert.ok(hit, 'a session record must exist');
    assert.match(hit.h, /^[0-9a-f]{64}$/, 'the stored value must be a sha256 hex digest');
  } finally { await srv.close(); setMode(undefined); }
});

test('a denied integration URL makes zero requests (c10)', async () => {
  const calls = [];
  const spy = (url, opts) => { calls.push({ url, opts }); return Promise.resolve({ status: 200, body: '{}' }); };
  const r = await validateIntegration('gitlab', { token: 'x', url: 'http://169.254.169.254/' }, { httpGet: spy });
  assert.strictEqual(r.ok, false);
  assert.match(String(r.message), /URL policy/i);
  assert.strictEqual(calls.length, 0, 'the policy must refuse before any request is made');
});

test('the connection is pinned to the vetted address (c11)', async () => {
  const prev = process.env.NEUROSPLOIT_INTEGRATION_HOSTS;
  process.env.NEUROSPLOIT_INTEGRATION_HOSTS = 'pinned.example';
  const calls = [];
  let resolutions = 0;
  const spy = (url, opts) => { calls.push({ url, opts }); return Promise.resolve({ status: 200, body: '{"username":"x"}' }); };
  const resolve = async () => { resolutions += 1; return [{ address: '93.184.216.34' }]; };
  try {
    const r = await validateIntegration('gitlab', { token: 'x', url: 'https://pinned.example' }, {
      httpGet: spy, resolve,
    });
    assert.strictEqual(r.ok, true, JSON.stringify(r));
    assert.strictEqual(resolutions, 1, 'the gate resolves exactly once');
    assert.strictEqual(calls.length, 1);
    assert.strictEqual(calls[0].opts.address, '93.184.216.34',
      'the request must carry the address the policy vetted, so a re-resolve cannot redirect it');
  } finally {
    if (prev === undefined) delete process.env.NEUROSPLOIT_WEB_AUTH;
    if (prev === undefined) delete process.env.NEUROSPLOIT_INTEGRATION_HOSTS;
    else process.env.NEUROSPLOIT_INTEGRATION_HOSTS = prev;
  }
});

test('the SPA bootstrap is wired and /api/auth/status answers (c12)', async () => {
  const js = fs.readFileSync(path.join(ROOT, 'web', 'public', 'app.js'), 'utf8');
  assert.match(js, /\/api\/auth\/status/, 'boot must ask the server for the auth mode');
  assert.match(js, /\/api\/auth\/login/, 'the one-time token must be exchangeable');
  assert.match(js, /history\.replaceState/, '?token= must be stripped from the URL');
  assert.match(js, /showAuthOverlay/, 'a 401 must produce the overlay');

  setMode(undefined);
  const srv = await startServer({ port: 0 });
  try {
    const st = await fetch(`${srv.url}/api/auth/status`);
    assert.strictEqual(st.status, 200);
    assert.strictEqual((await st.json()).auth, 'none');
  } finally { await srv.close(); setMode(undefined); }
});

test('a 500 does not leak a stack (c13)', async () => {
  setMode(undefined);
  const srv = await startServer({ port: 0 });
  try {
    const res = await fetch(`${srv.url}/api/config/vault`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: '{not json',
    });
    assert.strictEqual(res.status, 500, 'a malformed body currently surfaces as a server error');
    const body = await res.json();
    assert.ok(body.error, 'the client gets a message');
    assert.ok(!('stack' in body), 'no stack may be returned');
    assert.ok(!('path' in body), 'no internal path may be returned');
    assert.ok(!/\n\s+at /.test(JSON.stringify(body)), 'no stack frames may be embedded');
  } finally { await srv.close(); setMode(undefined); }
});
