'use strict';
// SEC-001 criterion 5 — /api/meta must not disclose absolute filesystem paths to
// a peer that is not on loopback. The test drives the production `metaPayload`
// and `isLoopback` helpers, so widening either one fails here.

const test = require('node:test');
const assert = require('node:assert');

const { metaPayload, isLoopback } = require('../server.js');

test('loopback detection covers the whole 127/8 range and ::1 (c5/failure mode)', () => {
  for (const a of ['127.0.0.1', '127.0.0.2', '127.1.2.3', '::1', '::ffff:127.0.0.1']) {
    assert.strictEqual(isLoopback(a), true, `${a} is loopback`);
  }
  for (const a of ['10.0.0.5', '192.168.1.10', '203.0.113.9', '::ffff:10.0.0.1', '', null, 'localhost']) {
    assert.strictEqual(isLoopback(a), false, `${a} is not loopback`);
  }
});

test('loopback peer receives version, binary and root (c5)', () => {
  const body = metaPayload('127.0.0.1');
  assert.deepStrictEqual(Object.keys(body).sort(), ['binary', 'root', 'version']);
});

test('remote peer receives version only (c5)', () => {
  const body = metaPayload('203.0.113.9');
  assert.deepStrictEqual(Object.keys(body), ['version'],
    `absolute paths leaked to a remote peer: ${JSON.stringify(body)}`);
});

test('a 127.0.0.2 peer is still treated as local (c5)', () => {
  const body = metaPayload('127.0.0.2');
  assert.ok('root' in body, '127.0.0.2 is loopback and must not be denied');
});
