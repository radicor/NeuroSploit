'use strict';
// SEC-007c — idempotency. These drive the production helpers directly: a
// successful HTTP launch spawns the CLI, so the HTTP path is exercised only where
// it cannot spawn (see the note in the completion report).

const test = require('node:test');
const assert = require('node:assert');

const { idempotencyKey, bodyDigest, withIdempotency, duplicateLaunch } = require('../server.js');

function req(headers) { return { headers }; }

test('an absent or malformed key is null (c1 / TN-1)', () => {
  assert.strictEqual(idempotencyKey(req({})), null);
  assert.strictEqual(idempotencyKey(req({ 'idempotency-key': 'short' })), null, 'under 8 chars');
  assert.strictEqual(idempotencyKey(req({ 'idempotency-key': 'x'.repeat(129) })), null, 'over 128 chars');
  assert.strictEqual(idempotencyKey(req({ 'idempotency-key': '  abcdefgh  ' })), 'abcdefgh');
});

test('the digest ignores key order at every level (c7 / TN-3)', () => {
  assert.strictEqual(bodyDigest({ a: 1, b: 2 }), bodyDigest({ b: 2, a: 1 }));
  assert.strictEqual(bodyDigest({ a: 1, n: { x: 1, y: 2 } }), bodyDigest({ n: { y: 2, x: 1 }, a: 1 }));
  assert.notStrictEqual(bodyDigest({ a: 1, b: 2 }), bodyDigest({ a: 1, b: 3 }));
  assert.notStrictEqual(bodyDigest({ a: [1, 2] }), bodyDigest({ a: [2, 1] }), 'array order is semantic');
});

test('the same key and body executes once and replays (c1 / TN-3)', async () => {
  let runs = 0;
  const fn = async () => { runs += 1; return { status: 200, body: { id: `job-${runs}` } }; };
  const digest = bodyDigest({ mode: 'run', target: 'http://example.com' });

  const a = await withIdempotency('key-aaaa-1', digest, fn);
  const b = await withIdempotency('key-aaaa-1', digest, fn);

  assert.strictEqual(runs, 1, 'the second call must not execute');
  assert.strictEqual(a.response.body.id, 'job-1');
  assert.deepStrictEqual(b.response, a.response, 'the stored response is replayed verbatim');
  assert.strictEqual(b.replayed, true);
});

test('the same key with a different body is a 422 and does not execute (c2 / TN-2)', async () => {
  let runs = 0;
  const fn = async () => { runs += 1; return { status: 200, body: { id: 'x' } }; };
  await withIdempotency('key-bbbb-1', bodyDigest({ target: 'a' }), fn);
  const bad = await withIdempotency('key-bbbb-1', bodyDigest({ target: 'b' }), fn);

  assert.strictEqual(bad.ok, false);
  assert.strictEqual(bad.status, 422);
  assert.match(String(bad.error), /different body/i);
  assert.strictEqual(runs, 1, 'a mismatched key must not run the request again');
});

test('no key means no dedupe (c3 / TN-1)', async () => {
  let runs = 0;
  const fn = async () => { runs += 1; return { status: 200, body: { id: String(runs) } }; };
  const digest = bodyDigest({ target: 'repeat' });
  await withIdempotency(null, digest, fn);
  await withIdempotency(null, digest, fn);
  assert.strictEqual(runs, 2, 'a repeat run without a key is legitimate');
});

test('a failure is not replayed (c1 — only successes are cached)', async () => {
  let runs = 0;
  const fn = async () => { runs += 1; return { status: 409, body: { error: 'already running' } }; };
  const digest = bodyDigest({ target: 'x' });
  await withIdempotency('key-cccc-1', digest, fn);
  await withIdempotency('key-cccc-1', digest, fn);
  assert.strictEqual(runs, 2, 'a 409 is a state observation, not a result to replay');
});

test('an entry older than 24h expires (c6 / TN-8)', async () => {
  let runs = 0;
  const fn = async () => { runs += 1; return { status: 200, body: { id: String(runs) } }; };
  const digest = bodyDigest({ target: 'expire' });
  const t0 = 1_000_000;
  await withIdempotency('key-dddd-1', digest, fn, { now: t0 });
  const within = await withIdempotency('key-dddd-1', digest, fn, { now: t0 + 1000 });
  assert.strictEqual(within.replayed, true, 'inside the window it replays');
  await withIdempotency('key-dddd-1', digest, fn, { now: t0 + 25 * 60 * 60 * 1000 });
  assert.strictEqual(runs, 2, 'past 24h the request runs again');
});

test('a duplicate running job is detected, a finished one is not (c4, c5 / TN-9, TN-1)', () => {
  const jobMap = new Map([
    ['j-running', { id: 'j-running', done: false, launch: { mode: 'run', target: 'http://a' } }],
    ['j-done', { id: 'j-done', done: true, launch: { mode: 'run', target: 'http://b' } }],
  ]);
  assert.strictEqual(duplicateLaunch('run', 'http://a', { jobMap }), 'j-running');
  assert.strictEqual(duplicateLaunch('run', 'http://b', { jobMap }), null, 'a finished job must not block a retest');
  assert.strictEqual(duplicateLaunch('greybox', 'http://a', { jobMap }), null, 'a different mode is a different launch');
  assert.strictEqual(duplicateLaunch('run', 'http://unknown', { jobMap }), null);
});
