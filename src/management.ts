import { randomUUID } from 'node:crypto';
import ssh2 from 'ssh2';
import { z } from 'zod';
import type { Config } from './config.js';
import { checkTarget } from './config.js';
import { HttpError } from './auth.js';
import { Store, type User } from './db.js';

export const CredentialSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('password'), password: z.string().min(1).max(4096) }).strict(),
  z.object({ type: z.literal('key'), privateKey: z.string().min(32).max(32768), passphrase: z.string().max(4096).optional() }).strict(),
]);
export const ServerSchema = z.object({
  name: z.string().trim().min(1).max(80), address: z.string().min(1).max(80), port: z.number().int().min(1).max(65535),
  username: z.string().regex(/^[a-z_][a-z0-9_-]{0,31}$/).refine(value => value !== 'root', 'Use a dedicated non-root SSH account'),
  fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/), credential: CredentialSchema,
}).strict();
export const ServerPatch = ServerSchema.partial().extend({ enabled: z.boolean().optional(), revision: z.number().int().min(1) }).strict();
export const GrantSchema = z.object({ userId: z.string().uuid(), serverId: z.string().uuid(), diagnostics: z.boolean(), execute: z.boolean() }).strict();
export const UserAccessPatch = z.object({ enabled: z.boolean().optional(), role: z.enum(['admin', 'operator', 'viewer']).optional() }).strict();
export const publicUser = (user: User) => ({ id: user.id, username: user.username, role: user.role, enabled: !!user.enabled, mfaEnabled: !!user.totp_cipher, createdAt: user.created_at });

export function requireAdmin(store: Store, actor: User) {
  const current = store.user(actor.id);
  if (!current?.enabled || current.role !== 'admin' || current.auth_version !== actor.auth_version) throw new HttpError(403, 'دسترسی مدیر لازم است');
}
export function protectLastAdmin(store: Store, user: User, body: z.infer<typeof UserAccessPatch>) {
  if (user.role === 'admin' && user.enabled && (body.enabled === false || (body.role && body.role !== 'admin'))) {
    const count = store.db.prepare("SELECT count(*) AS n FROM users WHERE enabled=1 AND role='admin'").get() as { n: number };
    if (count.n <= 1) throw new HttpError(409, 'آخرین مدیر فعال را نمی‌توان غیرفعال کرد');
  }
}
function validateCredential(credential: z.infer<typeof CredentialSchema>) {
  if (credential.type === 'key') {
    const key = ssh2.utils.parseKey(credential.privateKey, credential.passphrase);
    if (key instanceof Error || Array.isArray(key) || !key.isPrivateKey()) throw new HttpError(400, 'کلید خصوصی یا عبارت عبور معتبر نیست');
  }
}

export class Management {
  constructor(private store: Store, private config: Config) {}
  users(actor: User) { requireAdmin(this.store, actor); return { users: (this.store.db.prepare('SELECT * FROM users ORDER BY created_at').all() as User[]).map(publicUser) }; }
  updateUserAccess(actor: User, id: string, input: unknown) {
    const body = UserAccessPatch.parse(input);
    if (!Object.keys(body).length) throw new HttpError(400, 'هیچ تغییری مشخص نشده است');
    return this.store.db.transaction(() => {
      requireAdmin(this.store, actor);
      const user = this.store.user(id); if (!user) throw new HttpError(404, 'حساب پیدا نشد');
      protectLastAdmin(this.store, user, body);
      this.store.db.prepare('UPDATE users SET enabled=?,role=?,auth_version=auth_version+1 WHERE id=?').run(body.enabled === undefined ? user.enabled : Number(body.enabled), body.role || user.role, id);
      this.store.audit(actor.id, 'account.updated', id);
      return { user: publicUser(this.store.user(id)!) };
    })();
  }
  createServer(actor: User, input: unknown) {
    requireAdmin(this.store, actor);
    const body = ServerSchema.parse(input), id = randomUUID(), address = checkTarget(this.config, body.address);
    validateCredential(body.credential);
    return this.store.db.transaction(() => {
      if (this.store.db.prepare('SELECT id FROM servers WHERE name=?').get(body.name)) throw new HttpError(409, 'نام سرور تکراری است');
      this.store.db.prepare('INSERT INTO servers(id,name,address,port,username,fingerprint,credential,created_at) VALUES (?,?,?,?,?,?,?,?)')
        .run(id, body.name, address, body.port, body.username, body.fingerprint, this.store.vault.seal(body.credential, `server:${id}`), Date.now());
      this.store.audit(actor.id, 'server.created', id);
      return { id };
    })();
  }
  registerServerWithKey(actor: User, input: unknown) {
    requireAdmin(this.store, actor);
    const body = ServerSchema.omit({ credential: true }).parse(input);
    const keys = ssh2.utils.generateKeyPairSync('ed25519');
    const server = this.createServer(actor, { ...body, credential: { type: 'key', privateKey: keys.private } });
    return { ...server, name: body.name, revision: 1, publicKey: keys.public, connectionState: 'not_verified',
      nextStep: 'Install this public key in the dedicated remote account authorized_keys, restricted to the gateway source IP. The private key stays encrypted in the gateway. Then run a fixed diagnostic to verify the connection.' };
  }
  updateServer(actor: User, id: string, input: unknown) {
    requireAdmin(this.store, actor);
    const body = ServerPatch.parse(input), server = this.store.server(id);
    if (!server) throw new HttpError(404, 'سرور پیدا نشد');
    if (body.credential) validateCredential(body.credential);
    const address = checkTarget(this.config, body.address || server.address);
    return this.store.db.transaction(() => {
      const update = this.store.db.prepare('UPDATE servers SET name=?,address=?,port=?,username=?,fingerprint=?,credential=?,enabled=?,revision=revision+1 WHERE id=? AND revision=?')
        .run(body.name || server.name, address, body.port || server.port, body.username || server.username, body.fingerprint || server.fingerprint,
          body.credential ? this.store.vault.seal(body.credential, `server:${server.id}`) : server.credential,
          body.enabled === undefined ? server.enabled : Number(body.enabled), server.id, body.revision);
      if (!update.changes) throw new HttpError(409, 'تنظیمات تغییر کرده است؛ صفحه را تازه کنید');
      this.store.audit(actor.id, 'server.updated', server.id);
      return { ok: true, revision: server.revision + 1 };
    })();
  }
  grants(actor: User) { requireAdmin(this.store, actor); return { grants: this.store.db.prepare('SELECT user_id AS userId,server_id AS serverId,diagnostics,execute FROM grants').all() }; }
  setGrant(actor: User, input: unknown) {
    requireAdmin(this.store, actor); const body = GrantSchema.parse(input);
    if (!this.store.user(body.userId) || !this.store.server(body.serverId)) throw new HttpError(404, 'حساب یا سرور پیدا نشد');
    this.store.db.transaction(() => {
      this.store.db.prepare('INSERT INTO grants(user_id,server_id,diagnostics,execute) VALUES (?,?,?,?) ON CONFLICT(user_id,server_id) DO UPDATE SET diagnostics=excluded.diagnostics,execute=excluded.execute')
        .run(body.userId, body.serverId, Number(body.diagnostics), Number(body.execute));
      this.store.audit(actor.id, 'grant.updated', body.serverId, { userId: body.userId, diagnostics: body.diagnostics, execute: body.execute });
    })();
    return { ok: true };
  }
  audit(actor: User) { requireAdmin(this.store, actor); return { events: this.store.db.prepare('SELECT seq,at,actor,action,resource,detail,mac FROM audit ORDER BY seq DESC LIMIT 200').all(), integrity: this.store.verifyAudit() }; }
  settings(actor: User) {
    requireAdmin(this.store, actor);
    return { mcpUrl: `${this.config.publicUrl}/mcp`, callbacks: this.config.redirects, requireMfa: this.config.requireMfa, timeoutSeconds: this.config.timeout,
      outputLimitBytes: this.config.outputLimit, concurrency: this.config.concurrency, retentionDays: this.config.retentionDays, refreshIdleDays: this.config.refreshIdleDays };
  }
  connections(actor: User) {
    const current = this.store.user(actor.id);
    if (!current?.enabled || current.auth_version !== actor.auth_version) throw new HttpError(401, 'حساب معتبر نیست');
    const rows = this.store.db.prepare("SELECT t.family,MAX(t.expires_at) AS expiresAt,c.metadata FROM tokens t JOIN clients c ON c.id=t.client_id WHERE t.user_id=? AND t.revoked=0 AND t.used=0 AND t.expires_at>? GROUP BY t.family").all(actor.id, Date.now()) as { family: string; expiresAt: number; metadata: string }[];
    return { connections: rows.map(row => ({ id: row.family, clientName: JSON.parse(row.metadata).client_name, expiresAt: row.expiresAt })) };
  }
  revokeConnection(actor: User, id: string) {
    const current = this.store.user(actor.id);
    if (!current?.enabled || current.auth_version !== actor.auth_version) throw new HttpError(401, 'حساب معتبر نیست');
    this.store.db.prepare('UPDATE tokens SET revoked=1 WHERE family=? AND user_id=?').run(id, actor.id);
    this.store.audit(actor.id, 'oauth.revoked', id); return { ok: true };
  }
}
