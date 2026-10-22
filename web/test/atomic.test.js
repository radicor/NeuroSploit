'use strict';
// SEC-014 — a torn save must cost at most the last write, and a corrupt file must
// be recovered or preserved rather than overwritten. These tests drive the
// exported primitives and the real config store.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { atomicWriteSync, readJson, writeConfig, readConfig } = require('../server.js');

const ROOT = path.resolve(__dirname, '..', '..');

function tmpdir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `ns-atomic-${tag}-`));
}

function leftovers(dir) {
  return fs.readdirSync(dir).filter((n) => n.includes('.tmp-'));
}

test('atomicWriteSync round-trips and rotates .bak (c7)', () => {
  const d = tmpdir('rotate');
  const p = path.join(d, 'runs.json');
  fs.writeFileSync(p, 'old');

  atomicWriteSync(p, 'new');

  assert.strictEqual(fs.readFileSync(p, 'utf8'), 'new');
  assert.strictEqual(fs.readFileSync(`${p}.bak`, 'utf8'), 'old');
  assert.deepStrictEqual(leftovers(d), [], 'no temp file may survive a successful write');
  fs.rmSync(d, { recursive: true, force: true });
});

test('a failed write leaves the previous file intact (c8 / TN-7)', () => {
  const d = tmpdir('fail');
  const p = path.join(d, 'state.json');
  fs.writeFileSync(p, '{"ok":true}');

  // Make the temp path unusable by occupying every candidate name's parent: the
  // simplest deterministic failure is a target whose parent cannot be written.
  const blocked = path.join(d, 'ro', 'state.json');
  fs.mkdirSync(path.join(d, 'ro'), { recursive: true });
  fs.chmodSync(path.join(d, 'ro'), 0o500);
  let threw = false;
  try { atomicWriteSync(blocked, 'x'); } catch { threw = true; }
  fs.chmodSync(path.join(d, 'ro'), 0o700);
  assert.ok(threw, 'writing into a read-only directory must throw');

  // the untouched file is still readable and still parses
  assert.deepStrictEqual(readJson(p, null), { ok: true });
  fs.rmSync(d, { recursive: true, force: true });
});

test('readJson: missing, valid, recovered, quarantined (c9 / TN-1/3/4)', () => {
  const d = tmpdir('read');

  // missing -> fallback, and no quarantine is created
  assert.deepStrictEqual(readJson(path.join(d, 'none.json'), []), []);
  assert.deepStrictEqual(fs.readdirSync(d), [], 'a missing file must not quarantine');

  // valid -> parsed
  const ok = path.join(d, 'ok.json');
  fs.writeFileSync(ok, '["a"]');
  assert.deepStrictEqual(readJson(ok, []), ['a']);

  // truncated main with a good .bak -> the .bak value
  const rec = path.join(d, 'rec.json');
  fs.writeFileSync(rec, '["a",');
  fs.writeFileSync(`${rec}.bak`, '["a","b"]');
  assert.deepStrictEqual(readJson(rec, []), ['a', 'b'], 'a good .bak must be preferred to quarantine');

  // both bad -> fallback plus a preserved copy of the corrupt bytes
  const bad = path.join(d, 'bad.json');
  fs.writeFileSync(bad, '{"trunc');
  fs.writeFileSync(`${bad}.bak`, 'nope');
  assert.deepStrictEqual(readJson(bad, []), []);
  const q = fs.readdirSync(d).find((n) => n.startsWith('bad.json.corrupt-'));
  assert.ok(q, 'the corrupt file must be preserved');
  assert.strictEqual(fs.readFileSync(path.join(d, q), 'utf8'), '{"trunc', 'bytes must match the original');
  fs.rmSync(d, { recursive: true, force: true });
});

test('the config store uses the primitives (c10)', async () => {
  const name = `sec014-${process.pid}`;
  const file = path.join(ROOT, '.neurosploit', `${name}.json`);
  try {
    await writeConfig(name, [{ id: 'a' }, { id: 'b' }]);
    assert.deepStrictEqual(await readConfig(name), [{ id: 'a' }, { id: 'b' }]);

    // a second save rotates the first into .bak
    await writeConfig(name, [{ id: 'c' }]);
    assert.strictEqual(JSON.parse(fs.readFileSync(`${file}.bak`, 'utf8'))[0].id, 'a',
      '.bak must hold the previous config');

    // truncate the live file: the store must recover, not silently return []
    fs.writeFileSync(file, '[{"id":');
    // .bak holds the *previous* save — the first write here — so recovery
    // returns both of its entries, not the single-entry latest write.
    assert.deepStrictEqual(await readConfig(name), [{ id: 'a' }, { id: 'b' }],
      'a truncated config must recover from .bak rather than read as empty');
  } finally {
    for (const f of [file, `${file}.bak`]) { try { fs.rmSync(f, { force: true }); } catch { /* gone */ } }
    try {
      for (const n of fs.readdirSync(path.join(ROOT, '.neurosploit'))) {
        if (n.startsWith(`${name}.json.corrupt-`)) fs.rmSync(path.join(ROOT, '.neurosploit', n), { force: true });
      }
    } catch { /* no config dir */ }
  }
});
