'use strict';
// SEC-007c — per-name config locks, finished-job pruning, and the two remedies the
// SEC-007b verdict routed here (malformed JSON -> 400; token-file mode asserted on
// a freshly created file).

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { startServer, withConfigLock, pruneJobs, readConfig } = require('../server.js');

const ROOT = path.resolve(__dirname, '..', '..');
const TOKEN_FILE = path.join(ROOT, '.neurosploit', 'console-token');
const CONFIG_DIR = path.join(ROOT, '.neurosploit');

function setMode(m) {
  if (m === undefined) delete process.env.NEUROSPLOIT_WEB_AUTH;
  else process.env.NEUROSPLOIT_WEB_AUTH = m;
}

test('50 concurrent config adds all persist, with no temp residue (c8 / TN-4)', async () => {
  const srv = await startServer({ port: 0 });
  const name = `sec007c-${process.pid}`;
  try {
    const posts = Array.from({ length: 50 }, (_, i) => fetch(`${srv.url}/api/config/repos`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: `${name}-${i}`, url: `https://example.com/${i}` }),
    }));
    const results = await Promise.all(posts);
    for (const r of results) assert.strictEqual(r.status, 200);

    const stored = await readConfig('repos');
    const mine = stored.filter((r) => String(r.name || '').startsWith(name));
    assert.strictEqual(mine.length, 50, `expected 50 persisted entries, got ${mine.length}`);

    const leftovers = fs.readdirSync(CONFIG_DIR).filter((f) => f.includes('.tmp-'));
    assert.deepStrictEqual(leftovers, [], 'a lock cycle must not leave a temp file');
  } finally {
    await srv.close();
    const stored = await readConfig('repos');
    const kept = stored.filter((r) => !String(r.name || '').startsWith(name));
    const { writeConfig } = require('../server.js');
    await writeConfig('repos', kept);
  }
});

test('a throwing body releases the lock (c9 / TN-5)', async () => {
  const name = `throw-${process.pid}`;
  await assert.rejects(
    withConfigLock(name, async () => { throw new Error('boom'); }),
    /boom/,
  );
  // the next call for the same name must proceed rather than deadlock
  const out = await withConfigLock(name, async () => 'after');
  assert.strictEqual(out, 'after');
});

test('different names are not serialised (c10)', async () => {
  const order = [];
  const a = withConfigLock(`a-${process.pid}`, async () => {
    order.push('a-start');
    await new Promise((r) => setTimeout(r, 40));
    order.push('a-end');
  });
  const b = withConfigLock(`b-${process.pid}`, async () => {
    order.push('b-start');
  });
  await Promise.all([a, b]);
  // b must not wait for a: its start precedes a's end
  assert.ok(order.indexOf('b-start') < order.indexOf('a-end'),
    `different names must overlap, got ${order.join(',')}`);
});

test('the same name is serialised (c9)', async () => {
  const order = [];
  const name = `serial-${process.pid}`;
  const a = withConfigLock(name, async () => {
    order.push('a-start');
    await new Promise((r) => setTimeout(r, 30));
    order.push('a-end');
  });
  const b = withConfigLock(name, async () => { order.push('b-start'); });
  await Promise.all([a, b]);
  assert.deepStrictEqual(order, ['a-start', 'a-end', 'b-start'], 'the second call waits for the first');
});

test('pruning evicts finished jobs only (c11 / TN-6)', () => {
  const now = 10_000_000;
  const jobMap = new Map([
    ['old-done', { id: 'old-done', done: true, finishedAt: now - 120_000 }],
    ['old-running', { id: 'old-running', done: false, finishedAt: now - 120_000 }],
    ['fresh-done', { id: 'fresh-done', done: true, finishedAt: now - 1000 }],
    ['no-timestamp', { id: 'no-timestamp', done: true }],
  ]);
  const removed = pruneJobs(60_000, { now, jobMap });

  assert.strictEqual(removed, 1, 'only the old finished job is evicted');
  assert.strictEqual(jobMap.has('old-done'), false);
  assert.strictEqual(jobMap.has('old-running'), true, 'a running job must never be evicted');
  assert.strictEqual(jobMap.has('fresh-done'), true, 'inside the window it stays');
  assert.strictEqual(jobMap.has('no-timestamp'), true, 'no finish time means never evict');
});

test('malformed JSON is a 400 and leaves the vault untouched (c12)', async () => {
  setMode(undefined);
  const srv = await startServer({ port: 0 });
  const { writeConfig } = require('../server.js');
  await writeConfig('vault', { apiKey: 'unchanged-value' });
  try {
    const res = await fetch(`${srv.url}/api/config/vault`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: '{not json',
    });
    assert.strictEqual(res.status, 400, "malformed JSON is the client's error");
    const body = await res.json();
    assert.ok(body.error, 'the client gets a message');
    assert.ok(!('stack' in body), 'no stack may leak');

    const stored = await readConfig('vault');
    assert.strictEqual(stored.apiKey, 'unchanged-value', 'a refused body must not mutate state');
  } finally {
    await srv.close();
    await writeConfig('vault', {});
    setMode(undefined);
  }
});

test('the token-file mode is asserted on a freshly created file (c13)', async () => {
  // Delete first: a stale 0600 file would keep the check green even if the
  // creation path widened to 0644 — a warm-machine detector proves nothing.
  try { fs.rmSync(TOKEN_FILE, { force: true }); } catch { /* absent */ }
  setMode('token');
  const srv = await startServer({ port: 0 });
  try {
    // token mode mints the token at startup, so the one-time login URL exists
    // before any request is made.
    assert.ok(fs.existsSync(TOKEN_FILE), 'a token-mode start must create the token file');
    const mode = fs.statSync(TOKEN_FILE).mode & 0o777;
    assert.strictEqual(mode, 0o600, `a freshly created token file must be 600, got ${mode.toString(8)}`);
  } finally { await srv.close(); setMode(undefined); }
});
