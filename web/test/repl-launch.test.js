'use strict';
// SEC-023 — the REPL script is line-oriented. A newline in any interpolated
// value writes an extra `/command` line into the child's input, and the
// stdin gate (SEC-003) never sees it because it guards the live dock, not
// this file. Each field gets its own test: the per-conjunct rule, per field.

const test = require('node:test');
const assert = require('node:assert');

const path = require('node:path');
const fs = require('node:fs');

const { buildReplScript, authArgs, sanitizeLaunch } = require('../server.js');

const INJECTED = '3\n/proxy http://evil';

// field, a valid value. `recon` is a text field; the rest are integers
// except budget, which also accepts "unlimited".
const FIELDS = [
  ['votes', '2'],
  ['chainDepth', 2],
  ['recon', 'normal'],
  ['maxAgents', 2],
  ['budget', '1000'],
  ['tokenLimit', '5000'],
];

for (const [field, valid] of FIELDS) {
  test(`${field} cannot smuggle a REPL line`, () => {
    const body = { mode: 'run', target: 'http://target.example', [field]: INJECTED };
    assert.throws(
      () => buildReplScript(body),
      (err) => {
        assert.strictEqual(err.status, 400, `${field}: refusal must be a 400, got ${err.status}`);
        assert.strictEqual(err.field, field, `${field}: refusal must name the field, got ${err.field}`);
        return true;
      },
      `${field} accepted an injected newline`,
    );
  });

  test(`${field} still accepts a valid value`, () => {
    const lines = buildReplScript({ mode: 'run', target: 'http://target.example', [field]: valid });
    assert.ok(lines.length > 0, `${field}: a valid value must still build a script`);
  });
}

test('no injected value can add a line (sweep)', () => {
  const base = { mode: 'run', target: 'http://target.example' };
  for (const [field] of FIELDS) {
    for (const payload of ['3\n/proxy http://evil', '3\r/quit', 'normal\n/budget 999']) {
      assert.throws(
        () => buildReplScript({ ...base, [field]: payload }),
        /./,
        `${field} accepted ${JSON.stringify(payload)}`,
      );
    }
  }
});

test('a valid script has no line beyond the fields it was given', () => {
  const lines = buildReplScript({
    mode: 'run',
    target: 'http://target.example',
    votes: '2',
    chainDepth: 2,
    recon: 'normal',
    maxAgents: 2,
    budget: '10',
    tokenLimit: '20',
  });
  // Every line must start with a known REPL command; an injected line would
  // arrive as a second command inside one string, which this catches.
  for (const line of lines) {
    assert.match(line, /^\/[a-z][a-z-]*( .*)?$/, `unexpected line: ${JSON.stringify(line)}`);
    assert.ok(!line.includes('\n'), `line carries a newline: ${JSON.stringify(line)}`);
  }
});

test('unlimited budget still emits no budget line', () => {
  const lines = buildReplScript({
    mode: 'run',
    target: 'http://target.example',
    budget: 'unlimited',
  });
  assert.ok(
    !lines.some((l) => l.startsWith('/budget')),
    'budget=unlimited must not emit a budget line',
  );
});

test('a non-integer numeric field is refused, not coerced', () => {
  for (const field of ['votes', 'chainDepth', 'maxAgents', 'tokenLimit']) {
    assert.throws(
      () => buildReplScript({ mode: 'run', target: 'http://target.example', [field]: '1e9' }),
      (err) => err.field === field,
      `${field} accepted a non-integer`,
    );
  }
});

// ---------------------------------------------------------------- C2 / C3
test('--scope-file names the materialized file, and the file holds the rules (C2)', () => {
  const fixture = path.join(process.cwd(), 'test', `.scope-${process.pid}.json`);
  const rules = { hard: ['target.example'], exclude: ['admin.example'], soft: { observe_only: true } };
  fs.writeFileSync(fixture, JSON.stringify(rules));
  try {
    const args = authArgs({ scopePath: fixture });
    const i = args.indexOf('--scope-file');
    assert.ok(i > -1, 'argv must carry --scope-file — without it the wizard rules never reach the child');
    assert.strictEqual(args[i + 1], fixture);
    // Assert the FILE at the named path, not the flag: a flag with an empty or
    // different file is the defect this criterion exists for.
    const written = JSON.parse(fs.readFileSync(args[i + 1], 'utf8'));
    assert.deepStrictEqual(written.exclude, ['admin.example']);
    assert.deepStrictEqual(written.soft, { observe_only: true });
  } finally {
    fs.rmSync(fixture, { force: true });
  }
});

test('--execution-mode reaches argv, and yolo only behind consent (C3)', () => {
  const base = authArgs({});
  const i = base.indexOf('--execution-mode');
  assert.ok(i > -1, 'the resolved mode must be explicit in argv');
  assert.strictEqual(base[i + 1], 'scoped', 'omitting the field must resolve to scoped');

  const yolo = authArgs({ executionMode: 'yolo', acceptUnfenced: true });
  assert.strictEqual(yolo[yolo.indexOf('--execution-mode') + 1], 'yolo');

  assert.throws(
    () => authArgs({ executionMode: 'yolo' }),
    (e) => e.status === 400 && e.field === 'executionMode',
    'yolo without acceptUnfenced must be refused at this layer',
  );
  assert.throws(
    () => authArgs({ executionMode: 'isolated', acceptUnfenced: true }),
    (e) => e.field === 'executionMode',
    'isolated must be refused, never accepted-and-ignored',
  );
});

// ------------------------------------------------------------------- C4
test('a relaunch record keeps the authorization surface (C4)', () => {
  const fixture = path.join(process.cwd(), 'test', `.scope-c4-${process.pid}.json`);
  fs.writeFileSync(fixture, JSON.stringify({ hard: ['target.example'] }));
  try {
    const body = {
      mode: 'run',
      target: 'http://target.example',
      inScope: ['extra.corp'],
      scopePath: fixture,
      policyProfile: 'strict',
      executionMode: 'scoped',
      intercept: 'burp',
      sandbox: 'docker',
      transport: 'tor',
      environment: 'staging',
      capability: 'SECRET-TOKEN',
    };
    const rec = sanitizeLaunch(body);

    // The record must carry the ceiling...
    assert.deepStrictEqual(rec.inScope, ['extra.corp']);
    assert.strictEqual(rec.policyProfile, 'strict');
    assert.strictEqual(rec.executionMode, 'scoped');
    assert.strictEqual(rec.intercept, 'burp');
    assert.strictEqual(rec.transport, 'tor');
    assert.strictEqual(rec.sandbox, 'docker', 'the sandbox name must survive, not be coerced to true');
    // ...but never the bearer credential.
    assert.ok(!('capability' in rec), 'the capability token must not be persisted');

    // And the relaunch argv built from that record carries the same members.
    const args = authArgs(rec);
    assert.ok(args.includes('--session-policy') && args.includes('strict'));
    assert.ok(args.includes('--intercept') && args.includes('burp'));
    assert.ok(args.includes('--sandbox') && args.includes('docker'));
    assert.ok(args.includes('--scope-file') && args.includes(fixture));
  } finally {
    fs.rmSync(fixture, { force: true });
  }
});
