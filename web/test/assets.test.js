'use strict';
// SEC-006 — a run artifact is produced while attacking a hostile target, so its
// bytes must never be rendered on the console's origin. These tests drive the
// exported `assetHeaders` and `newConfigItem`, and exercise a real
// /api/runs/:id/asset/* response through `startServer`.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { startServer, assetHeaders, newConfigItem } = require('../server.js');

const ROOT = path.resolve(__dirname, '..', '..');
const RUNS_DIR = path.join(ROOT, 'runs');
const RUN_ID = `ns-test-assets-${process.pid}`;

function makeRun() {
  const dir = path.join(RUNS_DIR, RUN_ID);
  fs.mkdirSync(path.join(dir, 'pocs'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'report.html'), '<html><body><script>alert(1)</script></body></html>');
  fs.writeFileSync(path.join(dir, 'pocs', 'probe.svg'), '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
  return dir;
}

test('report.html is served as an attachment, never text/html (c1)', async () => {
  const dir = makeRun();
  const srv = await startServer({ port: 0 });
  try {
    const res = await fetch(`${srv.url}/api/runs/${RUN_ID}/asset/report.html`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('content-type'), 'application/octet-stream',
      'a hostile-file type must not be advertised');
    assert.match(res.headers.get('content-disposition') || '', /^attachment/,
      'the browser must download, not render');
    assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
    assert.match(res.headers.get('content-security-policy') || '', /sandbox/);
  } finally {
    await srv.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('no extension yields a renderable type (c2)', () => {
  for (const ext of ['.html', '.htm', '.xhtml', '.xml', '.svg', '.js', '.css', '.json', '', '.weird']) {
    const h = assetHeaders(ext, `f${ext}`);
    assert.strictEqual(h['Content-Type'], 'application/octet-stream',
      `${ext || '(none)'} must be octet-stream`);
  }
});

test('the bytes still arrive unmodified (c3 / TN-1)', async () => {
  const dir = makeRun();
  const srv = await startServer({ port: 0 });
  try {
    const expected = fs.readFileSync(path.join(dir, 'pocs', 'probe.svg'), 'utf8');
    const res = await fetch(`${srv.url}/api/runs/${RUN_ID}/asset/pocs/probe.svg`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(await res.text(), expected, 'the download must be byte-identical');
  } finally {
    await srv.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('containment still refuses traversal and sibling ids (c4 / TN-6)', async () => {
  const dir = makeRun();
  const sibling = path.join(RUNS_DIR, `${RUN_ID}0`);
  fs.mkdirSync(sibling, { recursive: true });
  fs.writeFileSync(path.join(sibling, 'secret.txt'), 'sibling');
  const srv = await startServer({ port: 0 });
  try {
    const trav = await fetch(`${srv.url}/api/runs/${RUN_ID}/asset/../../etc/passwd`);
    assert.ok([400, 403, 404].includes(trav.status), `traversal returned ${trav.status}`);

    // a sibling run whose id merely starts with this one must not be reachable
    const sib = await fetch(`${srv.url}/api/runs/${RUN_ID}/asset/${path.basename(sibling)}/secret.txt`);
    assert.ok([400, 403, 404].includes(sib.status), `sibling access returned ${sib.status}`);
  } finally {
    await srv.close();
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(sibling, { recursive: true, force: true });
  }
});

test('a hostile filename cannot break out of the header (failure mode 1)', () => {
  const h = assetHeaders('.html', 'x"\r\nSet-Cookie: pwned=1\r\n"');
  const cd = h['Content-Disposition'];
  assert.ok(!/[\r\n]/.test(cd), `CRLF reached the header: ${JSON.stringify(cd)}`);
  const name = /filename="([^"]*)"/.exec(cd)[1];
  assert.ok(!name.includes('"'), `a quote survived in the filename: ${name}`);
});

test('a client id cannot be stored, other fields survive (c8 / TN-5)', () => {
  const item = newConfigItem({ id: "x'onmouseover=alert(1)", name: 'prod', url: 'https://git.example' });
  assert.match(item.id, /^[0-9a-f-]{36}$/, `expected a server UUID, got ${item.id}`);
  assert.strictEqual(item.name, 'prod', 'an over-broad strip must not drop name');
  assert.strictEqual(item.url, 'https://git.example');
  assert.ok(item.createdAt, 'createdAt is set server-side');

  // createdAt from the client is also overwritten, not trusted
  const withTs = newConfigItem({ name: 'a', createdAt: '1999-01-01T00:00:00.000Z' });
  assert.notStrictEqual(withTs.createdAt, '1999-01-01T00:00:00.000Z');
});

test('the config POST route ignores a client id end to end (c8)', async () => {
  const prev = fs.existsSync(path.join(ROOT, '.neurosploit'));
  const srv = await startServer({ port: 0 });
  try {
    const res = await fetch(`${srv.url}/api/config/repos`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: "evil');alert(1);//", name: `sec006-${process.pid}`, url: 'https://example.com/x' }),
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.notStrictEqual(body.id, "evil');alert(1);//", 'the client id must not be stored');
    assert.match(body.id, /^[0-9a-f-]{36}$/);
    assert.strictEqual(body.name, `sec006-${process.pid}`);

    // clean the entry back out so repeat runs stay idempotent
    const list = await (await fetch(`${srv.url}/api/config/repos`)).json();
    const made = list.find((r) => r.name === `sec006-${process.pid}`);
    if (made) await fetch(`${srv.url}/api/config/repos/${encodeURIComponent(made.id)}`, { method: 'DELETE' });
  } finally {
    await srv.close();
    void prev;
  }
});
