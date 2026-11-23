import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import ssh2 from 'ssh2';
import { sshExecutor, shellQuote } from '../src/ssh.js';
import { Store } from '../src/db.js';
import { target, testConfig } from './helpers.js';

const hostKey = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs1', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey;
const parsed = ssh2.utils.parseKey(hostKey); if (parsed instanceof Error || Array.isArray(parsed)) throw new Error('Invalid test key');
const fingerprint = `SHA256:${createHash('sha256').update(parsed.getPublicSSH()).digest('base64').replace(/=+$/, '')}`;
const clientKeys = ssh2.utils.generateKeyPairSync('ed25519', { passphrase: 'test-key-passphrase', cipher: 'aes256-cbc' });
const clientKey = ssh2.utils.parseKey(clientKeys.private, 'test-key-passphrase');
if (clientKey instanceof Error || Array.isArray(clientKey)) throw new Error('Invalid test client key');
async function sshFixture(mode: 'normal' | 'large' | 'hang' = 'normal', authMode: 'password' | 'key' = 'password') {
  let command = '', authenticated = false;
  const clients = new Set<any>();
  const server = new ssh2.Server({ hostKeys: [hostKey] }, client => {
    clients.add(client); client.on('error', () => {}); client.on('close', () => clients.delete(client));
    client.on('authentication', ctx => {
      if (ctx.username !== 'gptops') return ctx.reject();
      if (authMode === 'password' && ctx.method === 'password' && ctx.password === 'test-ssh-password') { authenticated = true; ctx.accept(); }
      else if (authMode === 'key' && ctx.method === 'publickey' && ctx.key.data.equals(clientKey.getPublicSSH()) && (!ctx.signature || clientKey.verify(ctx.blob!, ctx.signature, ctx.hashAlgo) === true)) { authenticated = !!ctx.signature; ctx.accept(); }
      else ctx.reject();
    });
    client.on('ready', () => client.on('session', accept => {
      const session = accept(); session.on('exec', (accept, _reject, info) => {
        command = info.command; const stream = accept(); stream.on('error', () => {});
        if (mode === 'hang') return;
        if (mode === 'large') { stream.write('x'.repeat(10000)); stream.exit(0); stream.end(); return; }
        stream.write('Linux test\npassword=hidden\n'); stream.stderr.write('test-ssh-password'); stream.exit(0); stream.end();
      });
    }));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('Bad address');
  return { port: address.port, command: () => command, authenticated: () => authenticated, async close() { for (const client of clients) client.end(); await new Promise<void>(resolve => server.close(() => resolve())); } };
}
test('real SSH transport pins the host, authenticates, quotes command and redacts output', async () => {
  const remote = await sshFixture(), config = testConfig(), store = new Store(':memory:', config.masterKey);
  try {
    const server = { ...target(store), port: remote.port, fingerprint }, command = "printf '%s' 'hello; $(whoami)'\necho done";
    const result = await sshExecutor(config)(server, { type: 'password', password: 'test-ssh-password' }, command, new AbortController().signal);
    assert.equal(result.outcome, 'completed'); assert.equal(result.exitCode, 0); assert.equal(result.remoteState, 'finished'); assert(remote.authenticated());
    assert.equal(remote.command(), `exec timeout --signal=TERM --kill-after=5s 60s /bin/sh -c ${shellQuote(command)}`);
    assert(!result.stdout.includes('hidden')); assert(!result.stderr.includes('test-ssh-password'));
  } finally { store.close(); await remote.close(); }
});
test('wrong host key fails before credentials are sent', async () => {
  const remote = await sshFixture(), config = testConfig(), store = new Store(':memory:', config.masterKey);
  try {
    const result = await sshExecutor(config)({ ...target(store), port: remote.port }, { type: 'password', password: 'test-ssh-password' }, 'id', new AbortController().signal);
    assert.equal(result.outcome, 'connection_error'); assert(!remote.authenticated()); assert.equal(remote.command(), '');
  } finally { store.close(); await remote.close(); }
});
test('encrypted Ed25519 private key authenticates over the real SSH protocol', async () => {
  const remote = await sshFixture('normal', 'key'), config = testConfig(), store = new Store(':memory:', config.masterKey);
  try {
    const result = await sshExecutor(config)({ ...target(store), port: remote.port, fingerprint }, { type: 'key', privateKey: clientKeys.private, passphrase: 'test-key-passphrase' }, 'uname -srmo', new AbortController().signal);
    assert.equal(result.outcome, 'completed'); assert.equal(result.exitCode, 0); assert(remote.authenticated());
  } finally { store.close(); await remote.close(); }
});
test('output limit aborts a real SSH channel and exposes truncation', async () => {
  const remote = await sshFixture('large'), config = testConfig({ OUTPUT_LIMIT_BYTES: '1024' }), store = new Store(':memory:', config.masterKey);
  try {
    const result = await sshExecutor(config)({ ...target(store), port: remote.port, fingerprint }, { type: 'password', password: 'test-ssh-password' }, 'id', new AbortController().signal);
    assert(result.truncated); assert(Buffer.byteLength(result.stdout) <= 1024); assert.equal(result.remoteState, 'unknown');
  } finally { store.close(); await remote.close(); }
});
test('cancellation closes a real SSH session and does not claim remote completion', async () => {
  const remote = await sshFixture('hang'), config = testConfig(), store = new Store(':memory:', config.masterKey), controller = new AbortController();
  try {
    const execution = sshExecutor(config)({ ...target(store), port: remote.port, fingerprint }, { type: 'password', password: 'test-ssh-password' }, 'sleep 100', controller.signal);
    setTimeout(() => controller.abort(), 250);
    const result = await execution; assert.equal(result.outcome, 'cancelled'); assert.equal(result.remoteState, 'unknown');
  } finally { store.close(); await remote.close(); }
});
