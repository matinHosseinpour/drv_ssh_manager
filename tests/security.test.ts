import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Vault, hashPassword, verifyPassword, totp, matchTotp, redact } from '../src/security.js';
import { Store } from '../src/db.js';
import { checkTarget, loadConfig } from '../src/config.js';
import { testConfig } from './helpers.js';

test('vault authenticates ciphertext and record context', () => {
  const vault = new Vault(randomBytes(32)), secret = { password: 'sensitive-password' }, encrypted = vault.seal(secret, 'server:a');
  assert.deepEqual(vault.open(encrypted, 'server:a'), secret); assert(!encrypted.includes(secret.password));
  assert.throws(() => vault.open(encrypted, 'server:b'));
  const bytes = Buffer.from(encrypted, 'base64'); bytes[30] = bytes[30]! ^ 1;
  assert.throws(() => vault.open(bytes.toString('base64'), 'server:a'));
});
test('password hashing uses independent salts and rejects wrong password', async () => {
  const first = await hashPassword('a-strong-test-password'), second = await hashPassword('a-strong-test-password');
  assert.notEqual(first, second); assert(await verifyPassword('a-strong-test-password', first)); assert(!await verifyPassword('wrong', first));
});
test('TOTP matches RFC 6238 vector with 6-digit truncation and prevents replay', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(totp(secret, 1), '287082'); assert.equal(matchTotp(secret, '287082', -1, 1), 1); assert.equal(matchTotp(secret, '287082', 1, 1), null);
});
test('target allowlist rejects DNS, rebinding vectors, metadata IP and unapproved ranges', () => {
  const config = testConfig(); assert.equal(checkTarget(config, '10.20.0.5'), '10.20.0.5');
  for (const address of ['example.com', '10.21.0.5', '169.254.169.254', '::ffff:127.0.0.1', 'fe80::1%eth0', '0.0.0.0', '224.0.0.1']) assert.throws(() => checkTarget(config, address));
  assert.throws(() => testConfig({ SSH_ALLOWED_CIDRS: '0.0.0.0/0' }));
});
test('production refuses HTTP, absent key and disabled MFA', () => {
  const env = { NODE_ENV: 'production', PUBLIC_URL: 'https://gateway.example.com', MASTER_KEY: randomBytes(32).toString('base64'), SSH_ALLOWED_CIDRS: '10.20.0.1/32' };
  assert.equal(loadConfig(env).production, true);
  assert.throws(() => loadConfig({ ...env, PUBLIC_URL: 'http://gateway.example.com' }));
  assert.throws(() => loadConfig({ ...env, REQUIRE_MFA: 'false' }));
  assert.throws(() => loadConfig({ ...env, MASTER_KEY: '' }));
});
test('audit chain detects changed or missing records', () => {
  const store = new Store(':memory:', randomBytes(32));
  try {
    store.audit('a', 'first'); store.audit('b', 'second'); assert.deepEqual(store.verifyAudit().valid, true);
    store.db.prepare("UPDATE audit SET actor='attacker' WHERE seq=1").run(); assert.equal(store.verifyAudit().valid, false);
  } finally { store.close(); }
});
test('output redaction removes known credentials, private keys, common secrets and terminal escapes', () => {
  const value = redact('password=hello token:secret Bearer abc.def known-ssh-secret \x1b[31mred\x1b[0m\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----', ['known-ssh-secret']);
  assert(!value.includes('hello')); assert(!value.includes('abc.def')); assert(!value.includes('known-ssh-secret')); assert(!value.includes('\x1b')); assert(!value.includes('\nabc\n'));
});
