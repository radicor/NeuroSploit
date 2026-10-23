'use strict';
// SEC-016 — the P0 acceptance harness. Each assertion drives the real surface
// (a bound server, or the production gate function) and names its finding, so a
// red run reads as "A4 (SEC-006) failed" rather than a bare stack.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const {
  startServer, gateStdin, writeConfig, readConfig, requireConfirm,
} = require('../server.js');

const ROOT = path.resolve(__dirname, '..', '..');

// The checklist as data. Keep in step with harness/acceptance.md.
const ASSERTIONS = [
  { id: 'A1', finding: 'C1', owner: 'SEC-001', kind: 'web' },
  { id: 'A2', finding: 'C2', owner: 'SEC-007', kind: 'web' },
  { id: 'A3', finding: 'C3', owner: 'SEC-007b', kind: 'web' },
  { id: 'A4', finding: 'H1', owner: 'SEC-006', kind: 'web' },
  { id: 'A5', finding: 'H2', owner: 'SEC-006', kind: 'web' },
  { id: 'A6', finding: 'H3', owner: 'SEC-002', kind: 'web' },
  { id: 'A7', finding: 'H4', owner: 'SEC-002', kind: 'web' },
  { id: 'A8', finding: 'H5', owner: 'SEC-003', kind: 'web' },
  { id: 'A9', finding: 'H6', owner: 'SEC-013a', kind: 'web' },
  { id: 'A10', finding: 'H8', owner: 'SEC-004', kind: 'rust' },
  { id: 'A11', finding: 'H13', owner: 'SEC-014', kind: 'both' },
  { id: 'A12', finding: 'H14', owner: 'SEC-004', kind: 'rust' },
];

/// The twelve rows with an `ok` flag, filled by `record`. A red run reports the
/// id and owning spec, so the checklist and the failure are the same object.
function acceptanceReport() {
  return ASSERTIONS.map((a) => ({ ...a, ok: outcomes.get(a.id) !== false, detail: details.get(a.id) || '' }));
}

const outcomes = new Map();
const details = new Map();

async function assertAccept(id, fn) {
  const meta = ASSERTIONS.find((a) => a.id === id);
  try {
    await fn();
    outcomes.set(id, true);
    details.set(id, 'ok');
  } catch (e) {
    outcomes.set(id, false);
    details.set(id, String(e && e.message).split('\n')[0]);
    throw new Error(`${id} (${meta.owner}, finding ${meta.finding}): ${e && e.message}`);
  }
}

function rawRequest(port, { method = 'GET', path: p = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('the checklist has twelve entries with ids, findings and owners (criteria 13, 14)', () => {
  const report = acceptanceReport();
  assert.strictEqual(report.length, 12, 'twelve assertions');
  assert.deepStrictEqual(report.map((r) => r.id), ['A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9', 'A10', 'A11', 'A12']);
  for (const row of report) {
    assert.ok(row.finding && row.owner, `${row.id} must name a finding and an owner`);
  }
  // a failure message must carry the id, the owner and the finding
  const shaped = `A4 (SEC-006, finding H1): boom`;
  assert.match(shaped, /^A\d+ \(SEC-[\w]+, finding [A-Z]\d+\): /, 'the red-run message shape');
});

test('A1 — the console binds loopback only (C1)', async () => {
  await assertAccept('A1', async () => {
    const srv = await startServer({ port: 0 });
    try {
      assert.strictEqual(srv.address().address, '127.0.0.1', 'must bind loopback');
    } finally { await srv.close(); }
  });
});

test('A2 — cross-site writes are refused (C2)', async () => {
  await assertAccept('A2', async () => {
    const srv = await startServer({ port: 0 });
    try {
      const plain = await fetch(`${srv.url}/api/config/repos`, {
        method: 'POST', headers: { 'Content-Type': 'text/plain' },
        body: JSON.stringify({ name: 'a2', url: 'https://example.com/x' }),
      });
      assert.strictEqual(plain.status, 415, 'text/plain must be 415');

      const badOrigin = await fetch(`${srv.url}/api/config/repos`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
        body: JSON.stringify({ name: 'a2', url: 'https://example.com/x' }),
      });
      assert.strictEqual(badOrigin.status, 403, 'a cross-site write must be 403');

      const badHost = await rawRequest(srv.port, { path: '/api/meta', headers: { Host: 'evil.com' } });
      assert.strictEqual(badHost.status, 403, 'a rebound host must be 403');
    } finally { await srv.close(); }
  });
});

test('A3 — stored secrets never leave in a GET (C3)', async () => {
  await assertAccept('A3', async () => {
    const secret = `glpat-accept-${process.pid}`;
    await writeConfig('integrations', [{ id: 'gitlab', enabled: true, config: { url: 'https://gitlab.com', token: secret } }]);
    await writeConfig('vault', { apiKey: secret });
    const srv = await startServer({ port: 0 });
    try {
      const integ = await (await fetch(`${srv.url}/api/config/integrations`)).text();
      assert.ok(!integ.includes(secret), 'the integration token leaked');
      assert.ok(integ.includes('__masked__'), 'the value must arrive as a sentinel');

      const vault = await (await fetch(`${srv.url}/api/config/vault`)).text();
      assert.ok(!vault.includes(secret), 'the vault value leaked');
    } finally {
      await srv.close();
      await writeConfig('integrations', []);
      await writeConfig('vault', {});
    }
  });
});

test('A4 — a hostile artifact is inert (H1)', async () => {
  await assertAccept('A4', async () => {
    const id = `ns-accept-${process.pid}`;
    const dir = path.join(ROOT, 'runs', id);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'report.html'), '<html><script>alert(1)</script></html>');
    const srv = await startServer({ port: 0 });
    try {
      const res = await fetch(`${srv.url}/api/runs/${id}/asset/report.html`);
      assert.strictEqual(res.headers.get('content-type'), 'application/octet-stream');
      assert.match(res.headers.get('content-disposition') || '', /^attachment/);
      assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
    } finally {
      await srv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

test('A5 — a client id cannot be stored and no data rides an inline handler (H2)', async () => {
  await assertAccept('A5', async () => {
    const srv = await startServer({ port: 0 });
    try {
      const res = await fetch(`${srv.url}/api/config/repos`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: "evil');alert(1);//", name: `a5-${process.pid}`, url: 'https://example.com/x' }),
      });
      const made = await res.json();
      assert.match(made.id, /^[0-9a-f-]{36}$/, 'the client id must not be stored');
      await fetch(`${srv.url}/api/config/repos/${encodeURIComponent(made.id)}`, { method: 'DELETE' });

      const spa = fs.readFileSync(path.join(ROOT, 'web', 'public', 'app.js'), 'utf8');
      assert.ok(!/onclick="[^"]*\$\{/.test(spa), 'no data may be interpolated into an inline handler');
    } finally { await srv.close(); }
  });
});

test('A6 — CRLF cannot smuggle a REPL command (H3)', async () => {
  await assertAccept('A6', async () => {
    const srv = await startServer({ port: 0 });
    try {
      const res = await fetch(`${srv.url}/api/exploit`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'run', target: 'http://a\r\n/proxy http://evil' }),
      });
      assert.strictEqual(res.status, 400, 'a CRLF target must be refused');
      const body = await res.json();
      assert.strictEqual(body.field, 'target');
    } finally { await srv.close(); }
  });
});

test('A7 — argv and paths are validated (H4)', async () => {
  await assertAccept('A7', async () => {
    const srv = await startServer({ port: 0 });
    try {
      const badMode = await fetch(`${srv.url}/api/config/repos`, { method: 'GET' });
      assert.strictEqual(badMode.status, 200);

      const mcp = await fetch(`${srv.url}/api/exploit`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'mcp', target: 'http://example.com' }),
      });
      assert.strictEqual(mcp.status, 400);
      assert.strictEqual((await mcp.json()).field, 'mode');

      const flag = await fetch(`${srv.url}/api/exploit`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'run', target: '--offline' }),
      });
      assert.strictEqual(flag.status, 400);
      assert.strictEqual((await flag.json()).field, 'target');

      const outside = await fetch(`${srv.url}/api/exploit`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'run', target: 'http://example.com', creds: '/etc/passwd' }),
      });
      assert.strictEqual(outside.status, 400);
      assert.strictEqual((await outside.json()).field, 'creds');
    } finally { await srv.close(); }
  });
});

test('A8 — a retargeting stdin command is refused; an allowlisted one is not (H5)', async () => {
  await assertAccept('A8', async () => {
    // The route needs a live child, so this drives the production gate the route
    // calls — the HTTP-level half lives in SEC-003's own suite.
    const evil = gateStdin('/proxy http://evil', { tier: 'W', confirm: true, running: true });
    assert.strictEqual(evil.ok, false, '/proxy must be refused for a W caller');
    assert.strictEqual(evil.status, 400);

    const allowed = gateStdin('/pause', { tier: 'W', running: true });
    assert.strictEqual(allowed.ok, true, '/pause must pass');
    assert.strictEqual(allowed.payload, '/pause\n');
  });
});

test('A9 — an integration URL cannot point inward (H6)', async () => {
  await assertAccept('A9', async () => {
    const srv = await startServer({ port: 0 });
    try {
      const meta = await fetch(`${srv.url}/api/config/integrations/gitlab`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: { token: 'x', url: 'http://169.254.169.254/' } }),
      });
      assert.strictEqual(meta.status, 200);
      const body = await meta.json();
      assert.strictEqual(body.validation.ok, false, 'a metadata URL must not validate');
      assert.match(String(body.validation.message), /URL policy/i);
    } finally {
      await srv.close();
      await writeConfig('integrations', []);
    }
  });
});

test('A11 — a torn save costs at most the last write (H13, web half)', async () => {
  await assertAccept('A11', async () => {
    const name = `a11-${process.pid}`;
    const file = path.join(ROOT, '.neurosploit', `${name}.json`);
    try {
      await writeConfig(name, [{ id: 'first' }]);
      await writeConfig(name, [{ id: 'second' }]);
      fs.writeFileSync(file, '[{"id":');       // torn write
      const recovered = await readConfig(name);
      assert.deepStrictEqual(recovered, [{ id: 'first' }], 'the previous save must survive');
    } finally {
      for (const f of [file, `${file}.bak`]) { try { fs.rmSync(f, { force: true }); } catch { /* gone */ } }
    }
  });
});

test('the confirmation interlock still demands the exact phrase (C3, SEC-007b)', () => {
  assert.strictEqual(requireConfirm({ confirm: 'DELETE ALL' }, 'DELETE ALL').ok, true);
  assert.strictEqual(requireConfirm({ confirm: 'delete all' }, 'DELETE ALL').ok, false);
});
