'use strict';
// SEC-007 — the request pipeline: headers, Host allowlist, rate limit, Origin on
// unsafe methods, JSON-only bodies. These tests bind a real server; the Host
// cases use node:http because `fetch` refuses to set a Host header.

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const {
  startServer, securityHeaders, hostAllowed, originAllowed, enforceJsonType, rateLimit,
} = require('../server.js');

function rawRequest(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('helper edges: host, origin and content type (TN-1, TN-4)', () => {
  assert.strictEqual(hostAllowed('127.0.0.1:4173'), true, 'a port must not defeat the check');
  assert.strictEqual(hostAllowed('localhost:4173'), true);
  assert.strictEqual(hostAllowed('[::1]:4173'), true);
  assert.strictEqual(hostAllowed('evil.com'), false);
  assert.strictEqual(hostAllowed('evil.com:4173'), false);
  assert.strictEqual(hostAllowed(undefined), false);

  assert.strictEqual(originAllowed(undefined, '127.0.0.1:4173'), true, 'curl sends no Origin');
  assert.strictEqual(originAllowed('http://127.0.0.1:4173', '127.0.0.1:4173'), true);
  assert.strictEqual(originAllowed('https://evil.example', '127.0.0.1:4173'), false);

  assert.strictEqual(enforceJsonType('POST', 'application/json; charset=utf-8'), true);
  assert.strictEqual(enforceJsonType('POST', 'application/json'), true);
  assert.strictEqual(enforceJsonType('POST', 'text/plain'), false);
  assert.strictEqual(enforceJsonType('GET', 'text/plain'), true);
});

test('a foreign Host is refused, loopback hosts accepted (c1, c2, c10)', async () => {
  const srv = await startServer({ port: 0 });
  try {
    const evil = await rawRequest(srv.port, { path: '/api/meta', headers: { Host: 'evil.com' } });
    assert.strictEqual(evil.status, 403, 'a rebound Host must be refused');
    const evilGet = await rawRequest(srv.port, { path: '/', headers: { Host: 'evil.com' } });
    assert.strictEqual(evilGet.status, 403, 'Host is checked on safe methods too (rebinding reads)');

    const ok = await rawRequest(srv.port, { path: '/api/meta', headers: { Host: `127.0.0.1:${srv.port}` } });
    assert.strictEqual(ok.status, 200);
    const localhost = await rawRequest(srv.port, { path: '/api/meta', headers: { Host: `localhost:${srv.port}` } });
    assert.strictEqual(localhost.status, 200);
  } finally { await srv.close(); }
});

test('cross-origin unsafe requests are refused, same-origin and no-Origin pass (c3, c4)', async () => {
  const srv = await startServer({ port: 0 });
  try {
    const evil = await fetch(`${srv.url}/api/config/domains`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
      body: JSON.stringify({ domain: 'x.example' }),
    });
    assert.strictEqual(evil.status, 403, 'a cross-site write must be refused');

    const same = await fetch(`${srv.url}/api/config/domains`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: srv.url },
      body: JSON.stringify({ domain: `sec007-${process.pid}.example` }),
    });
    assert.strictEqual(same.status, 200, 'a same-origin write must pass');
    const made = await same.json();
    await fetch(`${srv.url}/api/config/domains/${encodeURIComponent(made.id)}`, { method: 'DELETE' });

    const noOrigin = await fetch(`${srv.url}/api/config/domains`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: `sec007-no-${process.pid}.example` }),
    });
    assert.strictEqual(noOrigin.status, 200, 'a client with no Origin (curl) must pass');
    const made2 = await noOrigin.json();
    await fetch(`${srv.url}/api/config/domains/${encodeURIComponent(made2.id)}`, { method: 'DELETE' });
  } finally { await srv.close(); }
});

test('a non-JSON body is 415 and never reaches the handler (c5, c6)', async () => {
  const srv = await startServer({ port: 0 });
  try {
    const before = await (await fetch(`${srv.url}/api/config/repos`)).json();

    const plain = await fetch(`${srv.url}/api/config/repos`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: JSON.stringify({ name: `sec007-${process.pid}`, url: 'https://example.com/x' }),
    });
    assert.strictEqual(plain.status, 415, 'text/plain must be refused before the route');

    const after = await (await fetch(`${srv.url}/api/config/repos`)).json();
    assert.strictEqual(after.length, before.length, 'no entry may be created by a refused body');

    const okType = await fetch(`${srv.url}/api/config/repos`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ name: `sec007-ok-${process.pid}`, url: 'https://example.com/y' }),
    });
    assert.strictEqual(okType.status, 200, 'a charset suffix must still count as JSON');
    const made = await okType.json();
    await fetch(`${srv.url}/api/config/repos/${encodeURIComponent(made.id)}`, { method: 'DELETE' });
  } finally { await srv.close(); }
});

test('security headers are on static and API responses (c7)', async () => {
  const srv = await startServer({ port: 0 });
  try {
    const expected = securityHeaders();
    for (const p of ['/', '/api/meta']) {
      const res = await fetch(`${srv.url}${p}`);
      for (const [k, v] of Object.entries(expected)) {
        assert.strictEqual(res.headers.get(k.toLowerCase()), v, `${p} is missing ${k}`);
      }
    }
  } finally { await srv.close(); }
});

test('the launch bucket refuses past its limit with Retry-After (c8)', async () => {
  const srv = await startServer({ port: 0 });
  try {
    // mode:"mcp" is refused by the validator (400) but still consumes a token,
    // so this drains the bucket without spawning an engagement.
    const seen = [];
    for (let i = 0; i < 7; i += 1) {
      const res = await fetch(`${srv.url}/api/exploit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'mcp', target: 'http://example.com' }),
      });
      seen.push(res.status);
      if (res.status === 429) {
        assert.ok(res.headers.get('retry-after'), '429 must carry Retry-After');
        assert.strictEqual(Number(res.headers.get('retry-after')) > 0, true);
      }
    }
    assert.strictEqual(seen[0], 400, 'the first launch attempt passes the limiter');
    assert.strictEqual(seen[6], 429, `the 7th launch attempt must be rate limited, got ${seen.join(',')}`);
  } finally { await srv.close(); }
});

test('rate limits are keyed per caller (c9 / TN-6)', () => {
  const a = [];
  for (let i = 0; i < 6; i += 1) a.push(rateLimit(`caller-a-${process.pid}`, 'launch').ok);
  assert.deepStrictEqual(a, [true, true, true, true, true, true]);
  const blocked = rateLimit(`caller-a-${process.pid}`, 'launch');
  assert.strictEqual(blocked.ok, false);
  assert.ok(blocked.retryAfter >= 1);

  const other = rateLimit(`caller-b-${process.pid}`, 'launch');
  assert.strictEqual(other.ok, true, 'a different caller must not inherit the refusal');
});
