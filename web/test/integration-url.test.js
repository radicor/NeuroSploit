'use strict';
// SEC-013a — an integration URL is fetched with the operator's credential, so the
// host must be the provider's and must not be private. Every name-host case
// injects a resolver: the post-resolve rule is the point, and the suite must not
// depend on DNS.

const test = require('node:test');
const assert = require('node:assert');

const { isPrivateAddress, integrationUrlAllowed, validateIntegration } = require('../server.js');

const publicResolve = async () => [{ address: '93.184.216.34', family: 4 }];
const privateResolve = async () => [{ address: '127.0.0.1', family: 4 }];
const allow = (provider, url, opts = {}) =>
  integrationUrlAllowed(provider, url, { resolve: publicResolve, ...opts });

test('isPrivateAddress classifies the private ranges (c6 / TN-4)', () => {
  for (const ip of ['169.254.169.254', '127.0.0.1', '127.1.2.3', '10.0.0.5', '172.16.0.1',
    '172.31.255.254', '192.168.1.1', '100.64.0.1', '0.0.0.0', '::1', '::ffff:127.0.0.1',
    'fe80::1', 'fc00::1', 'fd12::1', 'nonsense', '']) {
    assert.strictEqual(isPrivateAddress(ip), true, `${JSON.stringify(ip)} must be private/fail-closed`);
  }
  for (const ip of ['93.184.216.34', '8.8.8.8', '172.32.0.1', '2606:4700:4700::1111']) {
    assert.strictEqual(isPrivateAddress(ip), false, `${ip} must be public`);
  }
});

test('gitlab default and its subdomains are accepted (c1, c2 / TN-1)', async () => {
  for (const url of ['https://gitlab.com', 'https://sub.gitlab.com', 'https://a.b.gitlab.com']) {
    const r = await allow('gitlab', url);
    assert.strictEqual(r.ok, true, `${url} must be allowed: ${r.error}`);
  }
  for (const url of ['https://acme.atlassian.net', 'https://acme.atlassian.net/']) {
    assert.strictEqual((await allow('jira', url)).ok, true, `${url} must be allowed`);
  }
});

test('the suffix trap is refused (c3 / TN-2)', async () => {
  for (const url of ['https://gitlab.com.evil.test', 'https://notgitlab.com',
    'https://evilgitlab.com', 'https://gitlab.company.example']) {
    const r = await allow('gitlab', url);
    assert.strictEqual(r.ok, false, `${url} must be refused (suffix must be dot-anchored)`);
  }
});

test('the userinfo trap is judged by host (c4 / TN-7)', async () => {
  const r = await allow('gitlab', 'https://gitlab.com@evil.test/');
  assert.strictEqual(r.ok, false, 'userinfo must not smuggle an unlisted host past the check');
});

test('https is required (c5 / TN-3)', async () => {
  assert.strictEqual((await allow('gitlab', 'http://gitlab.com')).ok, false, 'plain http must fail');
  assert.strictEqual((await allow('gitlab', 'ftp://gitlab.com')).ok, false, 'ftp must fail');
  assert.strictEqual((await allow('gitlab', 'https://gitlab.com')).ok, true);
});

test('private IP literals are refused however they are spelled (c6 / TN-4)', async () => {
  for (const url of ['https://169.254.169.254/', 'https://127.0.0.1/', 'https://10.0.0.5/',
    'https://192.168.1.1/', 'https://[::1]/', 'https://0.0.0.0/']) {
    const r = integrationUrlAllowed('gitlab', url);
    assert.strictEqual((await r).ok, false, `${url} must be refused`);
  }
});

test('a public name resolving to a private address is refused (c7 / TN-5)', async () => {
  const prev = process.env.NEUROSPLOIT_INTEGRATION_HOSTS;
  process.env.NEUROSPLOIT_INTEGRATION_HOSTS = 'internal.example.com';
  try {
    const denied = await integrationUrlAllowed('gitlab', 'https://internal.example.com', { resolve: privateResolve });
    assert.strictEqual(denied.ok, false, 'name resolving to loopback must be refused');
    assert.match(String(denied.error), /private|resolve/i);

    const ok = await integrationUrlAllowed('gitlab', 'https://internal.example.com', { resolve: publicResolve });
    assert.strictEqual(ok.ok, true, 'the same name with a public address must be allowed');

    // any private address in a mixed answer refuses the URL
    const mixed = await integrationUrlAllowed('gitlab', 'https://internal.example.com', {
      resolve: async () => [{ address: '93.184.216.34' }, { address: '10.0.0.7' }],
    });
    assert.strictEqual(mixed.ok, false, 'a mixed resolve result must be refused');

    // a resolver failure is a refusal, never a pass
    const boom = await integrationUrlAllowed('gitlab', 'https://internal.example.com', {
      resolve: async () => { throw new Error('ENOTFOUND'); },
    });
    assert.strictEqual(boom.ok, false, 'resolver error must fail closed');
  } finally {
    if (prev === undefined) delete process.env.NEUROSPLOIT_INTEGRATION_HOSTS;
    else process.env.NEUROSPLOIT_INTEGRATION_HOSTS = prev;
  }
});

test('a self-hosted host can be allowed by the operator (c8 / TN-6)', async () => {
  const prev = process.env.NEUROSPLOIT_INTEGRATION_HOSTS;
  process.env.NEUROSPLOIT_INTEGRATION_HOSTS = 'git.corp.test';
  try {
    const r = await integrationUrlAllowed('gitlab', 'https://git.corp.test', { resolve: publicResolve });
    assert.strictEqual(r.ok, true, 'the operator escape hatch must work');
    // a wildcard would disable the check, so it is ignored
    process.env.NEUROSPLOIT_INTEGRATION_HOSTS = '*';
    const star = await integrationUrlAllowed('gitlab', 'https://anything.example', { resolve: publicResolve });
    assert.strictEqual(star.ok, false, '"*" must not become a blanket allow');
  } finally {
    if (prev === undefined) delete process.env.NEUROSPLOIT_INTEGRATION_HOSTS;
    else process.env.NEUROSPLOIT_INTEGRATION_HOSTS = prev;
  }
});

test('validateIntegration refuses before fetching (c9)', async () => {
  const r = await validateIntegration('gitlab', { token: 'x', url: 'http://169.254.169.254/' });
  assert.strictEqual(r.ok, false, 'a metadata URL must not validate');
  assert.match(String(r.message), /URL policy/i, `message must name the policy: ${r.message}`);

  const r2 = await validateIntegration('jira', { email: 'a@b.c', token: 't', domain: 'http://10.0.0.5' });
  assert.strictEqual(r2.ok, false, 'jira must refuse a private domain');
  assert.match(String(r2.message), /URL policy/i);
});
