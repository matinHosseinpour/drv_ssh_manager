import express, { type ErrorRequestHandler } from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { z, ZodError } from 'zod';
import { Store } from './db.js';
import type { Config } from './config.js';
import { hashPassword, newTotpSecret, randomToken } from './security.js';
import { HttpError, sessionAuth } from './auth.js';
import { oauthRouter } from './oauth.js';
import { mcpRouter, visibleServers } from './mcp.js';
import { Jobs } from './jobs.js';
import { Management, protectLastAdmin, publicUser } from './management.js';

const UserSchema = z.object({ username: z.string().trim().regex(/^[a-zA-Z0-9_.@-]{3,80}$/), password: z.string().min(14).max(256), role: z.enum(['admin', 'operator', 'viewer']) }).strict();

export async function createApp(store: Store, config: Config, jobs: Jobs) {
  const app = express(), auth = sessionAuth(store, config), management = new Management(store, config);
  const dummyHash = await hashPassword(randomToken());
  app.disable('x-powered-by'); app.set('trust proxy', config.trustedProxies.length ? config.trustedProxies : false);
  app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], formAction: ["'self'"], frameAncestors: ["'none'"], upgradeInsecureRequests: config.production ? [] : null } }, strictTransportSecurity: config.production ? undefined : false, referrerPolicy: { policy: 'strict-origin' } }));
  app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.get('host') !== new URL(config.publicUrl).host) return res.status(421).json({ error: 'Invalid Host' });
    if (req.get('origin') && req.get('origin') !== config.publicUrl) return res.status(403).json({ error: 'Invalid Origin' });
    next();
  });
  app.use(express.json({ limit: '96kb' }));
  app.use(express.urlencoded({ extended: false, limit: '16kb', parameterLimit: 20 }));
  app.use(cookieParser());
  const limit = (max: number, windowMs = 60000) => rateLimit({ windowMs, limit: max, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'درخواست‌های زیاد؛ کمی صبر کنید' } });
  app.use('/api', limit(240)); app.use('/mcp', limit(240));
  app.use('/oauth/register', limit(10, 3600000));
  app.use('/oauth/token', limit(60)); app.use('/oauth/revoke', limit(60)); app.use('/oauth/authorize', limit(30));
  app.get('/healthz', (_req, res) => {
    const healthy = jobs.healthy();
    res.status(healthy ? 200 : 503).json({ status: healthy ? 'ok' : 'worker_unavailable' });
  });
  app.get('/api/session', (req, res) => {
    const identity = auth.read(req);
    res.json(identity ? { user: publicUser(identity.user), csrf: identity.csrf, mcpUrl: `${config.publicUrl}/mcp` } : { user: null, requireMfa: config.requireMfa });
  });
  app.post('/api/login', limit(15, 900000), async (req, res) => {
    if (req.get('origin') !== config.publicUrl || !req.is('application/json')) throw new HttpError(403, 'Invalid login origin or content type');
    const body = z.object({ username: z.string().trim().max(80), password: z.string().max(256), otp: z.string().max(6).default('') }).strict().parse(req.body);
    const result = await auth.login(body.username, body.password, body.otp, dummyHash);
    const old = auth.read(req); if (old) store.db.prepare('DELETE FROM sessions WHERE hash=?').run(old.sessionHash);
    res.cookie(auth.cookieName, result.token, { ...auth.cookieOptions, maxAge: 8 * 3600000 });
    res.json({ user: publicUser(result.user), csrf: result.csrf });
  });
  app.use(oauthRouter(store, config));
  app.use(mcpRouter(store, config, jobs));
  app.use('/api', auth.requireSession, auth.csrf);
  app.post('/api/logout', (req, res) => {
    store.db.prepare('DELETE FROM sessions WHERE hash=?').run(req.identity!.sessionHash);
    res.clearCookie(auth.cookieName, auth.cookieOptions); res.json({ ok: true });
  });
  app.get('/api/servers', (req, res) => res.json({ servers: visibleServers(store, req.identity!.user, true) }));
  app.get('/api/jobs', (req, res) => res.json({ jobs: jobs.list(req.identity!.user) }));
  app.post('/api/jobs', (req, res) => res.status(201).json(jobs.create(req.identity!.user, req.body)));
  app.get('/api/jobs/:id', (req, res) => res.json(jobs.get(req.identity!.user, String(req.params.id))));
  app.post('/api/jobs/:id/cancel', (req, res) => res.json(jobs.cancel(req.identity!.user, String(req.params.id))));
  app.post('/api/jobs/:id/approve', auth.admin, (req, res) => {
    const { commandHash } = z.object({ commandHash: z.string().regex(/^[a-f0-9]{64}$/) }).strict().parse(req.body);
    res.json(jobs.approve(req.identity!.user, String(req.params.id), commandHash));
  });
  app.post('/api/jobs/:id/reject', auth.admin, (req, res) => res.json(jobs.cancel(req.identity!.user, String(req.params.id), true)));
  app.get('/api/connections', (req, res) => res.json(management.connections(req.identity!.user)));
  app.delete('/api/connections/:id', (req, res) => res.json(management.revokeConnection(req.identity!.user, String(req.params.id))));
  app.post('/api/password', async (req, res) => {
    const { currentPassword, password } = z.object({ currentPassword: z.string().max(256), password: z.string().min(14).max(256) }).strict().parse(req.body);
    const { verifyPassword } = await import('./security.js');
    const user = req.identity!.user;
    if (!await verifyPassword(currentPassword, user.password_hash)) throw new HttpError(401, 'رمز فعلی معتبر نیست');
    const hash = await hashPassword(password);
    const changed = store.db.prepare('UPDATE users SET password_hash=?,auth_version=auth_version+1 WHERE id=? AND auth_version=?').run(hash, user.id, user.auth_version);
    if (!changed.changes) throw new HttpError(409, 'حساب تغییر کرده است');
    store.audit(user.id, 'account.password_changed'); res.clearCookie(auth.cookieName, auth.cookieOptions); res.json({ ok: true });
  });

  app.use('/api/admin', auth.admin);
  app.get('/api/admin/users', (req, res) => res.json(management.users(req.identity!.user)));
  app.post('/api/admin/users', async (req, res) => {
    const body = UserSchema.parse(req.body), hash = await hashPassword(body.password), id = randomUUID(), secret = newTotpSecret();
    auth.checkAdmin(req);
    store.db.transaction(() => {
      if (store.db.prepare('SELECT id FROM users WHERE username=?').get(body.username)) throw new HttpError(409, 'نام کاربری تکراری است');
      store.db.prepare('INSERT INTO users(id,username,password_hash,role,totp_cipher,created_at) VALUES (?,?,?,?,?,?)').run(id, body.username, hash, body.role, store.vault.seal(secret, `totp:${id}`), Date.now());
      store.audit(req.identity!.user.id, 'account.created', id, { role: body.role });
    })();
    res.status(201).json({ user: publicUser(store.user(id)!), mfaSecret: secret, provisioningUri: `otpauth://totp/ServerConnector:${encodeURIComponent(body.username)}?secret=${secret}&issuer=ServerConnector&digits=6&period=30` });
  });
  app.patch('/api/admin/users/:id', async (req, res) => {
    const body = z.object({ enabled: z.boolean().optional(), role: z.enum(['admin', 'operator', 'viewer']).optional(), password: z.string().min(14).max(256).optional(), resetMfa: z.boolean().optional() }).strict().parse(req.body);
    if (!Object.keys(body).length) throw new HttpError(400, 'هیچ تغییری مشخص نشده است');
    const hash = body.password ? await hashPassword(body.password) : undefined;
    const secret = body.resetMfa ? newTotpSecret() : undefined;
    auth.checkAdmin(req);
    store.db.transaction(() => {
      const user = store.user(String(req.params.id)); if (!user) throw new HttpError(404, 'حساب پیدا نشد');
      protectLastAdmin(store, user, body);
      store.db.prepare('UPDATE users SET enabled=?,role=?,password_hash=?,totp_cipher=?,last_totp_step=?,auth_version=auth_version+1 WHERE id=?')
        .run(body.enabled === undefined ? user.enabled : Number(body.enabled), body.role || user.role, hash || user.password_hash,
          secret ? store.vault.seal(secret, `totp:${user.id}`) : user.totp_cipher, secret ? -1 : user.last_totp_step, user.id);
      store.audit(req.identity!.user.id, 'account.updated', user.id);
    })();
    res.json({ user: publicUser(store.user(String(req.params.id))!), ...(secret ? { mfaSecret: secret } : {}) });
  });
  app.post('/api/admin/servers', (req, res) => res.status(201).json(management.createServer(req.identity!.user, req.body)));
  app.patch('/api/admin/servers/:id', (req, res) => res.json(management.updateServer(req.identity!.user, String(req.params.id), req.body)));
  app.get('/api/admin/grants', (req, res) => res.json(management.grants(req.identity!.user)));
  app.put('/api/admin/grants', (req, res) => res.json(management.setGrant(req.identity!.user, req.body)));
  app.get('/api/admin/audit', (req, res) => res.json(management.audit(req.identity!.user)));
  app.get('/api/admin/settings', (req, res) => res.json(management.settings(req.identity!.user)));
  app.use('/api', (_req, res) => res.status(404).json({ error: 'مسیر پیدا نشد' }));
  app.use(express.static(fileURLToPath(new URL('../public', import.meta.url)), { etag: false, maxAge: 0 }));
  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  const handleError: ErrorRequestHandler = (error, req, res, _next) => {
    if (res.headersSent) return res.end();
    if (error instanceof ZodError) return res.status(400).json({ error: 'ورودی معتبر نیست', fields: error.issues.map(issue => ({ path: issue.path.join('.'), message: issue.message })) });
    if (error instanceof HttpError) return res.status(error.status).json({ error: error.message });
    if (error?.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large' });
    if (error instanceof SyntaxError) return res.status(400).json({ error: 'Invalid request body' });
    if (error?.code?.startsWith('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'اطلاعات تکراری است یا با وضعیت فعلی سازگار نیست' });
    // Do not serialize requests, SSH errors, SQL parameters or credential-bearing bodies.
    console.error(JSON.stringify({ event: 'request_failed', method: req.method, errorType: error?.constructor?.name || 'Error' }));
    res.status(500).json({ error: 'خطای داخلی؛ شناسهٔ کار را در گزارش رخدادها بررسی کنید' });
  };
  app.use(handleError);
  return app;
}
