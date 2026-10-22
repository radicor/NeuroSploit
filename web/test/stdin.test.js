'use strict';
// SEC-003 — the live-dock stdin allowlist. The gate is driven directly: a job's
// child process is created by startJob, so there is no seam to inject a fake one
// without spawning the CLI (see the completion report).

const test = require('node:test');
const assert = require('node:assert');

const { classifyStdinLine, gateStdin, REPL_COMMANDS, OPERATOR_COMMANDS } = require('../server.js');

test('the interactive subset passes (c1 / TN-1)', () => {
  for (const cmd of ['/pause', '/continue', '/resume', '/stop', '/status', '/agents', '/help']) {
    assert.strictEqual(REPL_COMMANDS.has(cmd), true, `${cmd} must be allowed`);
    const g = gateStdin(cmd, { tier: 'W', running: true });
    assert.strictEqual(g.ok, true, `${cmd} must pass: ${g.error}`);
    assert.strictEqual(g.action, 'write');
    assert.strictEqual(g.payload, `${cmd}\n`, 'the payload is the exact bytes for the child');
  }
});

test('a retargeting command needs tier D and confirm (c2, c3 / TN-7)', () => {
  // tier too low, even with confirm
  let g = gateStdin('/proxy http://evil', { tier: 'W', confirm: true, running: true });
  assert.strictEqual(g.ok, false);
  assert.strictEqual(g.status, 400);

  // destructive tier but no confirm
  g = gateStdin('/target http://evil', { tier: 'D', confirm: false, running: true });
  assert.strictEqual(g.ok, false);

  // both, and the arguments survive intact
  g = gateStdin('/target http://evil', { tier: 'D', confirm: true, running: true });
  assert.strictEqual(g.ok, true);
  assert.strictEqual(g.payload, '/target http://evil\n');

  for (const cmd of ['/quit', '/creds', '/key', '/scope', '/sandbox']) {
    assert.strictEqual(OPERATOR_COMMANDS.has(cmd), true, `${cmd} must be operator-only`);
    assert.strictEqual(gateStdin(cmd, { tier: 'W', confirm: true, running: true }).ok, false);
  }
});

test('an unknown slash command is refused, never forwarded (c4 / TN-8)', () => {
  for (const line of ['/etc/passwd', '/delete-all', '/PAUSE', '/Quit', '/target=x', '/help-me']) {
    const g = gateStdin(line, { tier: 'D', confirm: true, running: true });
    assert.strictEqual(g.ok, false, `${line} must be refused`);
    assert.strictEqual(g.status, 400);
    assert.ok(!g.payload, 'a refused line must not produce a payload');
  }
});

test('case is not folded (c5 / TN-3)', () => {
  assert.strictEqual(classifyStdinLine('/pause').kind, 'allow');
  assert.strictEqual(classifyStdinLine('/PAUSE').kind, 'reject');
  assert.strictEqual(classifyStdinLine('/Pause').kind, 'reject');
});

test('the first token decides (c6 / TN-4)', () => {
  const a = classifyStdinLine('/pause now');
  assert.strictEqual(a.kind, 'allow');
  assert.strictEqual(a.command, '/pause', 'trailing words do not change the command');

  // '/target=x' is not '/target'
  assert.strictEqual(classifyStdinLine('/target=x').kind, 'reject');
});

test('Ctrl-C is a control action, not a byte write (c7 / TN-6)', () => {
  const stopped = gateStdin('\u0003', { running: false });
  assert.strictEqual(stopped.ok, false, 'nothing running means nothing to interrupt');
  assert.strictEqual(stopped.status, 400);

  const live = gateStdin('\u0003', { running: true });
  assert.strictEqual(live.ok, true);
  assert.strictEqual(live.action, 'signal', 'the route maps this to SIGINT');
  assert.strictEqual(live.payload, null, 'a raw 0x03 must never be written to the pipe');
});

test('a multi-line payload is refused (c8 / TN-9)', () => {
  for (const bad of ['/pause\n/target http://evil', '/pause\r\n/target http://evil', 'text\nmore']) {
    const g = gateStdin(bad, { tier: 'D', confirm: true, running: true });
    assert.strictEqual(g.ok, false, `a second line must not ride in: ${JSON.stringify(bad)}`);
    assert.strictEqual(g.status, 400);
  }
  // a trailing newline is the normal form and must still pass
  assert.strictEqual(gateStdin('/pause\n', { tier: 'W', running: true }).ok, true);
});

test('the payload cap is exact (c9 / TN-5)', () => {
  const atLimit = 'x'.repeat(65536);
  assert.strictEqual(gateStdin(atLimit, {}).ok, true, 'exactly 65536 bytes is allowed');
  const over = 'x'.repeat(65537);
  const g = gateStdin(over, {});
  assert.strictEqual(g.ok, false);
  assert.strictEqual(g.status, 413);
});

test('a refusal names the command and never the payload (c10)', () => {
  const secret = 'http://internal.example/?token=abc123';
  const g = gateStdin(`/unknown ${secret}`, { tier: 'D', confirm: true, running: true });
  assert.strictEqual(g.ok, false);
  assert.strictEqual(g.command, '/unknown');
  assert.ok(!String(g.error).includes('abc123'), 'the refusal must not echo the payload');
});

test('free text passes through unchanged (TN-1 body of the gate)', () => {
  const g = gateStdin('continue with the login flow', { tier: 'W', running: true });
  assert.strictEqual(g.ok, true);
  assert.strictEqual(g.payload, 'continue with the login flow\n');
});
