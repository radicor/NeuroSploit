'use strict';
// SEC-002 — the wizard's JSON must not become argv flags, REPL commands, or a
// path to an arbitrary file. These tests drive the exported production builders
// (`buildArgs`, `buildReplScript`) and the validators they use, so softening a
// guard fails here.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  MODE_ALLOWLIST, checkPositional, safeReplValue, confinePath, resolveRunDir,
  buildArgs, buildReplScript, materializeCreds, cleanupJobTemp,
} = require('../server.js');

const is400 = (field) => (e) => {
  assert.strictEqual(e.status, 400, `expected status 400, got ${e.status}: ${e.message}`);
  assert.strictEqual(e.field, field, `expected field ${field}, got ${e.field}`);
  return true;
};

// ---------------------------------------------------------------- criterion 1
test('every legitimate mode still launches (c1 / TN-1)', () => {
  for (const mode of ['run', 'whitebox', 'greybox', 'host', 'aitest', 'skills', 'cloud']) {
    assert.ok(MODE_ALLOWLIST.has(mode), `${mode} must be allowed`);
    const body = { mode, target: 'http://example.com', repo: 'owner/repo' };
    assert.doesNotThrow(() => buildArgs(body), `mode ${mode} must launch`);
  }
  // cloud is an alias, not a CLI subcommand
  assert.deepStrictEqual(buildArgs({ mode: 'cloud', target: 'aws' }).slice(0, 3),
    ['host', 'aws', '--cloud']);
});

// ---------------------------------------------------------------- criterion 2
test('unsupported modes are refused with a named field (c2)', () => {
  for (const mode of ['mcp', 'container', 'mobile', 'capability', 'internal', 'tui', 'rebuild']) {
    assert.throws(() => buildArgs({ mode, target: 'http://example.com' }), is400('mode'),
      `mode ${mode} must be refused`);
  }
});

// ------------------------------------------------------------ criteria 3 and 4
test('flag injection is refused, legitimate targets pass (c3)', () => {
  for (const bad of ['--offline', '-o', '--target=x', '-']) {
    assert.throws(() => buildArgs({ mode: 'run', target: 'http://example.com', focus: bad }), is400('focus'),
      `focus ${bad} must be refused`);
    assert.throws(() => buildArgs({ mode: 'run', target: bad }), is400('target'),
      `target ${bad} must be refused`);
  }
  for (const good of ['http://example.com', 'example.com:8080', '10.0.0.5/24']) {
    assert.doesNotThrow(() => buildArgs({ mode: 'run', target: good }), `target ${good} must pass`);
  }
});

test('command injection is refused, prose still passes (c4 / TN-4)', () => {
  assert.throws(() => buildArgs({ mode: 'run', target: 'http://a\r\n/proxy http://evil' }), is400('target'));
  assert.throws(() => buildArgs({ mode: 'run', target: 'http://a\nb' }), is400('target'));
  assert.throws(() => buildArgs({ mode: 'run', target: 'http://a\0b' }), is400('target'));
  // prose with spaces, punctuation and non-ASCII must survive
  assert.doesNotThrow(() => buildArgs({
    mode: 'run', target: 'http://example.com',
    objective: "find IDOR in the billing flow — don't skip 日本語",
  }));
});

// ---------------------------------------------------------------- criterion 5
test('a REPL command cannot be smuggled as a value (c5)', () => {
  assert.throws(() => buildReplScript({ mode: 'run', target: '/proxy http://evil' }), is400('target'));
  assert.throws(() => buildReplScript({ mode: 'run', target: 'http://a', creds: '/quit' }), is400('creds'));
  // paths and URLs contain '/' mid-string and must survive
  assert.doesNotThrow(() => buildReplScript({ mode: 'run', target: 'http://example.com/a/b' }));
  // CRLF in the REPL path too — a second line is a second command
  assert.throws(() => buildReplScript({ mode: 'run', target: 'http://a\r\n/quit' }), is400('target'));
});

test('safeReplValue draws the line at a leading slash (c5)', () => {
  assert.strictEqual(safeReplValue('/etc/creds.yaml', 'creds').ok, true);
  assert.strictEqual(safeReplValue('http://e.com/a/b', 'target').ok, true);
  assert.strictEqual(safeReplValue('/proxy http://evil', 'target').ok, false);
  assert.strictEqual(safeReplValue('  /quit', 'target').ok, false);
});

// ------------------------------------------------------- criteria 6, 7, 8, TN-2/3/5
function sandbox() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-002-'));
  const eng = path.join(base, 'eng');
  const engx = path.join(base, 'engx');
  fs.mkdirSync(eng, { recursive: true });
  fs.mkdirSync(engx, { recursive: true });
  fs.writeFileSync(path.join(eng, 'creds.yaml'), 'auth: x\n');
  fs.writeFileSync(path.join(engx, 'creds.yaml'), 'auth: x\n');
  fs.writeFileSync(path.join(base, 'outside.yaml'), 'auth: x\n');
  return { base, eng, engx };
}

test('path confinement holds against near-misses (c6 / TN-2)', () => {
  const { base, eng, engx } = sandbox();
  try {
    const inside = confinePath(path.join(eng, 'creds.yaml'), { roots: [eng] });
    assert.strictEqual(inside.ok, true, JSON.stringify(inside));

    assert.strictEqual(confinePath('/etc/passwd', { roots: [eng] }).ok, false, 'outside root');
    assert.strictEqual(confinePath(path.join(eng, '..', 'outside.yaml'), { roots: [eng] }).ok, false,
      'dot-dot escape');
    assert.strictEqual(confinePath(path.join(engx, 'creds.yaml'), { roots: [eng] }).ok, false,
      'sibling-prefix must not be treated as a child');

    // relative resolves inside the first root
    assert.strictEqual(confinePath('creds.yaml', { roots: [eng] }).ok, true);
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('a symlink cannot escape a root (c7 / TN-3)', () => {
  const { base, eng } = sandbox();
  try {
    fs.symlinkSync(path.join(base, 'outside.yaml'), path.join(eng, 'escape.yaml'));
    fs.symlinkSync(path.join(eng, 'creds.yaml'), path.join(eng, 'inside-link.yaml'));

    assert.strictEqual(confinePath(path.join(eng, 'escape.yaml'), { roots: [eng] }).ok, false,
      'symlink pointing outside the root must be rejected');
    assert.strictEqual(confinePath(path.join(eng, 'inside-link.yaml'), { roots: [eng] }).ok, true,
      'symlink pointing inside the root must be accepted');
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('a missing file is a client error, not a throw (c8 / TN-5)', () => {
  const { base, eng } = sandbox();
  try {
    const r = confinePath(path.join(eng, 'nope.yaml'), { roots: [eng] });
    assert.strictEqual(r.ok, false, 'ENOENT must be a 400-shaped result');
    assert.match(String(r.error), /exist|ENOENT/i);
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

// --------------------------------------------------------------- criterion 9
test('run ids cannot traverse (c9)', () => {
  assert.strictEqual(resolveRunDir('ns-abc123').ok, true);
  for (const bad of ['../etc', 'a/b', '.', '..', '', 'x\0y']) {
    assert.strictEqual(resolveRunDir(bad).ok, false, `id ${JSON.stringify(bad)} must be refused`);
  }
});

// -------------------------------------------------------------- criterion 10
test('materialized creds are private and clean up (c10)', async () => {
  const jobId = `ns-test-${process.pid}`;
  // materializeCreds is async — awaiting is the point, not incidental.
  const file = await materializeCreds({ auth: 'Authorization: Bearer tok' }, jobId);
  assert.ok(file && fs.existsSync(file), 'creds file must exist');
  const fileMode = fs.statSync(file).mode & 0o777;
  const dirMode = fs.statSync(path.dirname(file)).mode & 0o777;
  assert.strictEqual(fileMode, 0o600, `creds file mode ${fileMode.toString(8)} must be 600`);
  assert.strictEqual(dirMode, 0o700, `temp dir mode ${dirMode.toString(8)} must be 700`);

  cleanupJobTemp(jobId);
  assert.strictEqual(fs.existsSync(file), false, 'temp creds must be removed with the job');
});

// --------------------------------------------------------------- criterion 12
test('checkPositional trims and reports the field', () => {
  assert.deepStrictEqual(checkPositional('  spaced  ', 'focus'), { ok: true, value: 'spaced' });
  assert.strictEqual(checkPositional('', 'focus').ok, false);
  assert.strictEqual(checkPositional('x'.repeat(5000), 'focus').ok, false, 'length cap');
  assert.strictEqual(checkPositional(undefined, 'focus').ok, false);
});
