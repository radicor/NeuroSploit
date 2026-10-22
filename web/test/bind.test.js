'use strict';
// SEC-001 — the console must bind loopback by default and report the address it
// actually bound. These tests drive the exported production helpers
// (`startServer`, `bindAddress`, `bindBanner`) rather than re-implementing the
// formatting, so changing the production behaviour fails them.

const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const os = require('node:os');

const { startServer, bindAddress, bindBanner } = require('../server.js');

test('default binds loopback only (c1)', async () => {
  const srv = await startServer({ port: 0 });
  try {
    const addr = srv.address();
    assert.strictEqual(addr.address, '127.0.0.1', `bound ${addr.address}, expected loopback`);
    assert.ok(srv.port > 0, 'ephemeral port must be reported');

    // If this host has a non-loopback IPv4, a connection to that address on the
    // same port must be refused. Skipped (with a note) on loopback-only hosts.
    const other = Object.values(os.networkInterfaces()).flat()
      .find((i) => i && i.family === 'IPv4' && !i.internal);
    if (other) {
      await assert.rejects(
        new Promise((res, rej) => {
          const s = net.connect({ host: other.address, port: srv.port }, () => { s.destroy(); res(); });
          s.on('error', rej);
          setTimeout(() => { s.destroy(); rej(new Error('connect timeout')); }, 1500).unref();
        }),
        `port answered on ${other.address} — console is not loopback-only`
      );
    } else {
      assert.ok(true, 'no non-loopback interface on this host; bind address asserted only');
    }
  } finally { await srv.close(); }
});

test('banner equals the bound address (c2)', async () => {
  const lines = [];
  const original = console.log;
  console.log = (...a) => { lines.push(a.join(' ')); };
  let srv;
  try { srv = await startServer({ port: 0 }); } finally { console.log = original; }
  try {
    const addr = srv.address();
    const printed = lines.join('\n');
    assert.ok(printed.includes(`127.0.0.1:${addr.port}`),
      `banner must name the bound address; got ${JSON.stringify(printed)}`);
    assert.ok(!printed.includes('localhost'),
      'banner must not claim localhost any more');
  } finally { await srv.close(); }
});

test('explicit wildcard binds and warns naming the auth mode (c3)', async () => {
  const lines = [];
  const original = console.log;
  console.log = (...a) => { lines.push(a.join(' ')); };
  let srv;
  try { srv = await startServer({ port: 0, host: '0.0.0.0' }); } finally { console.log = original; }
  try {
    assert.strictEqual(srv.address().address, '0.0.0.0');
    const printed = lines.join('\n').toLowerCase();
    assert.ok(printed.includes('warning'), `expected a warning, got ${JSON.stringify(lines)}`);
    assert.ok(printed.includes('auth'), 'the warning must name the auth mode');
  } finally { await srv.close(); }
});

test('ipv6 loopback renders bracketed (c4)', () => {
  assert.strictEqual(bindAddress('::1'), '[::1]');
  assert.strictEqual(bindAddress('127.0.0.1'), '127.0.0.1');
  assert.strictEqual(bindAddress('0.0.0.0'), '0.0.0.0');
  assert.strictEqual(bindBanner('::1', 4173), 'http://[::1]:4173');
  assert.strictEqual(bindBanner('127.0.0.1', 4173), 'http://127.0.0.1:4173');
});

test('port 0 reports the real port (c6)', async () => {
  const srv = await startServer({ port: 0 });
  try {
    assert.notStrictEqual(srv.port, 0, 'must report the OS-assigned port, not the request');
    assert.strictEqual(srv.port, srv.address().port);
    assert.ok(srv.url.endsWith(`:${srv.port}`), `url ${srv.url} must carry the real port`);
  } finally { await srv.close(); }
});

test('startServer is idempotent per process (c6/failure mode)', async () => {
  const a = await startServer({ port: 0 });
  const b = await startServer({ port: 0 });
  try {
    assert.strictEqual(a.port, b.port, 'a second call must reuse the running listener');
  } finally { await a.close(); }
});
