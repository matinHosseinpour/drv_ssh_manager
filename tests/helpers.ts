import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import { loadConfig } from '../src/config.js';
import { Store, type User } from '../src/db.js';
import { hashPassword } from '../src/security.js';
import { Jobs } from '../src/jobs.js';
import { createApp } from '../src/app.js';
import type { Executor } from '../src/ssh.js';

export const TEST_PASSWORD = 'test-only-password-42!';
export const testConfig = (extra: Record<string, string> = {}) => loadConfig({ NODE_ENV: 'test', PUBLIC_URL: 'http://127.0.0.1:3080', MASTER_KEY: randomBytes(32).toString('base64'), SSH_ALLOWED_CIDRS: '127.0.0.1/32,10.20.0.0/24', REQUIRE_MFA: 'false', DATABASE_PATH: ':memory:', ...extra });
export async function user(store: Store, role: User['role'] = 'operator', name = randomUUID()) {
  const id = randomUUID();
  store.db.prepare('INSERT INTO users(id,username,password_hash,role,created_at) VALUES (?,?,?,?,?)').run(id, name, await hashPassword(TEST_PASSWORD), role, Date.now());
  return store.user(id)!;
}
export function target(store: Store) {
  const id = randomUUID();
  store.db.prepare('INSERT INTO servers(id,name,address,port,username,fingerprint,credential,created_at) VALUES (?,?,?,?,?,?,?,?)')
    .run(id, `server-${id}`, '127.0.0.1', 22, 'gptops', `SHA256:${'A'.repeat(43)}`, store.vault.seal({ type: 'password', password: 'test-ssh-password' }, `server:${id}`), Date.now());
  return store.server(id)!;
}
export function grant(store: Store, userId: string, serverId: string, diagnostics = true, execute = true) {
  store.db.prepare('INSERT OR REPLACE INTO grants(user_id,server_id,diagnostics,execute) VALUES (?,?,?,?)').run(userId, serverId, Number(diagnostics), Number(execute));
}
export const success: Executor = async () => ({ stdout: 'ok', stderr: '', exitCode: 0, signal: null, truncated: false, outcome: 'completed', remoteState: 'finished' });
export async function waitFor(fn: () => boolean, ms = 4000) { const start = Date.now(); while (!fn()) { if (Date.now() - start > ms) throw new Error('Condition timed out'); await new Promise(resolve => setTimeout(resolve, 20)); } }
async function freePort() {
  const server = createServer(); await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); const port = typeof address === 'object' && address ? address.port : 0;
  await new Promise<void>(resolve => server.close(() => resolve())); return port;
}
export async function fixture(execute: Executor = success) {
  const port = await freePort(), config = testConfig({ PUBLIC_URL: `http://127.0.0.1:${port}` }), store = new Store(':memory:', config.masterKey);
  const jobs = new Jobs(store, config, execute); jobs.start();
  const app = await createApp(store, config, jobs), server = app.listen(port, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  const request = (path: string, init: RequestInit = {}) => fetch(`${config.publicUrl}${path}`, { ...init, redirect: 'manual' });
  const login = async (account: User) => {
    const res = await request('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: config.publicUrl }, body: JSON.stringify({ username: account.username, password: TEST_PASSWORD, otp: '' }) });
    if (res.status !== 200) throw new Error(`Login failed: ${res.status}`);
    const body = await res.json() as { csrf: string };
    return { cookie: res.headers.get('set-cookie')!.split(';')[0]!, csrf: body.csrf };
  };
  return { config, store, jobs, request, login, async close() { await jobs.stop(); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); store.close(); } };
}
