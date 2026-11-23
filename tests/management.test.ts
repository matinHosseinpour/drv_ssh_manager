import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { fixture, target, user } from './helpers.js';
import { digest, randomToken } from '../src/security.js';
import { Management } from '../src/management.js';

test('management tools require both an administrator and explicit management consent; secrets remain in the gateway', async () => {
  const f = await fixture(); let client: Client | undefined;
  try {
    const admin = await user(f.store, 'admin', 'management-admin'), operator = await user(f.store, 'operator', 'management-operator'), server = target(f.store);
    const clientId = randomUUID(), family = randomUUID();
    f.store.db.prepare('INSERT INTO clients(id,metadata,created_at) VALUES (?,?,?)').run(clientId, JSON.stringify({ client_name: 'management test' }), Date.now());
    const connect = async (scope: string, account = admin) => {
      const token = randomToken();
      f.store.db.prepare('INSERT INTO tokens(hash,kind,family,user_id,client_id,resource,scope,auth_version,expires_at) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(digest(token), 'access', family, account.id, clientId, `${f.config.publicUrl}/mcp`, scope, account.auth_version, Date.now() + 600000);
      const next = new Client({ name: 'management-test', version: '1.0.0' });
      try {
        await next.connect(new StreamableHTTPClientTransport(new URL(`${f.config.publicUrl}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
        return next;
      } catch (error) { await next.close(); throw error; }
    };
    client = await connect('servers:access');
    assert(!(await client.listTools()).tools.some(tool => tool.name === 'register_server'));
    await client.close(); client = await connect('servers:access gateway:manage');
    const call = (name: string, args: Record<string, unknown> = {}) => client!.callTool({ name, arguments: args });
    const accounts = await call('list_users'); assert(!accounts.isError); assert(JSON.stringify(accounts).includes(operator.username));
    assert(!JSON.stringify(accounts).includes('scrypt$')); assert(!JSON.stringify(accounts).includes('totp_cipher'));
    const grant = await call('set_server_grant', { userId: operator.id, serverId: server.id, diagnostics: true, execute: false }); assert(!grant.isError);
    assert.equal((f.store.db.prepare('SELECT execute FROM grants WHERE user_id=?').get(operator.id) as { execute: number }).execute, 0);
    const disabled = await call('update_server', { serverId: server.id, revision: 1, enabled: false }); assert(!disabled.isError);
    const list = await call('list_servers'); assert(JSON.stringify(list).includes(server.id)); assert(JSON.stringify(list).includes('"revision":2')); assert(!JSON.stringify(list).includes('127.0.0.1'));
    assert((await call('update_server', { serverId: server.id, revision: 1, enabled: true })).isError);
    const enrolled = await call('register_server', { name: 'registered-through-mcp', address: '10.20.0.15', port: 22, username: 'gptops', fingerprint: `SHA256:${'A'.repeat(43)}` });
    assert(!enrolled.isError); const result = enrolled.structuredContent as { id: string; publicKey: string; connectionState: string };
    assert(result.publicKey.startsWith('ssh-ed25519 ')); assert.equal(result.connectionState, 'not_verified');
    assert(!JSON.stringify(enrolled).includes('PRIVATE KEY')); assert(!JSON.stringify(enrolled).includes('privateKey'));
    const stored = f.store.server(result.id)!; assert(!stored.credential.includes('PRIVATE KEY'));
    assert(f.store.vault.open<{ privateKey: string }>(stored.credential, `server:${stored.id}`).privateKey.includes('PRIVATE KEY'));
    const lastAdmin = await call('update_user_access', { userId: admin.id, enabled: false }); assert(lastAdmin.isError); assert.equal(f.store.user(admin.id)!.enabled, 1);
    const previous = operator.auth_version;
    assert(!(await call('update_user_access', { userId: operator.id, enabled: false })).isError);
    assert.equal(f.store.user(operator.id)!.auth_version, previous + 1);
    assert(!(await call('get_audit')).isError); assert(f.store.verifyAudit().valid);
    await client.close(); client = undefined;
    await assert.rejects(connect('servers:access gateway:manage', { ...operator, ...f.store.user(operator.id)! }));
  } finally { await client?.close(); await f.close(); }
});

test('management services enforce the same target, role, revision and final-admin boundaries as the web API', async () => {
  const f = await fixture();
  try {
    const management = new Management(f.store, f.config), admin = await user(f.store, 'admin'), viewer = await user(f.store, 'viewer'), server = target(f.store);
    assert.throws(() => management.setGrant(viewer, { userId: viewer.id, serverId: server.id, diagnostics: true, execute: true }));
    assert.throws(() => management.updateUserAccess(admin, admin.id, { role: 'viewer' }));
    assert.throws(() => management.updateServer(admin, server.id, { revision: 1, address: '169.254.169.254' }));
    const update = management.updateServer(admin, server.id, { revision: 1, name: 'renamed-by-manager' }); assert.equal(update.revision, 2);
    assert.throws(() => management.updateServer(admin, server.id, { revision: 1, enabled: false }));
    const session = await f.login(admin);
    const response = await f.request('/api/servers', { headers: { Cookie: session.cookie } });
    assert((await response.text()).includes('renamed-by-manager'));
  } finally { await f.close(); }
});
