import { Router, type Request } from 'express';
import { randomUUID, createHash } from 'node:crypto';
import { z } from 'zod';
import type { Config } from './config.js';
import { Store } from './db.js';
import { HttpError, sessionAuth } from './auth.js';
import { digest, equal, randomToken } from './security.js';

const SCOPE = 'servers:access';
export const MANAGEMENT_SCOPE = 'gateway:manage';
export const DEFAULT_SCOPES = `${SCOPE} ${MANAGEMENT_SCOPE}`;
const escape = (value: string) => value.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
type Authorization = { client_id: string; redirect_uri: string; code_challenge: string; state: string; resource: string; scope: string };
type TokenRow = { hash: string; family: string; user_id: string; client_id: string; resource: string; scope: string; auth_version: number; expires_at: number; revoked: number; used: number };

export function bearerIdentity(store: Store, config: Config, req: Request) {
  const header = req.get('authorization');
  if (!header?.startsWith('Bearer ') || header.length > 200) return undefined;
  const row = store.db.prepare("SELECT * FROM tokens WHERE hash=? AND kind='access' AND used=0 AND revoked=0 AND expires_at>?").get(digest(header.slice(7)), Date.now()) as TokenRow | undefined;
  const user = row && store.user(row.user_id);
  const scopes = new Set(row?.scope.split(' ') || []);
  if (!row || row.resource !== `${config.publicUrl}/mcp` || !scopes.has(SCOPE) || [...scopes].some(scope => ![SCOPE, MANAGEMENT_SCOPE].includes(scope)) || !user?.enabled || user.auth_version !== row.auth_version || (scopes.has(MANAGEMENT_SCOPE) && user.role !== 'admin')) return undefined;
  return { user, scopes, connectionId: row.family };
}
export function bearerUser(store: Store, config: Config, req: Request) { return bearerIdentity(store, config, req)?.user; }

export function oauthRouter(store: Store, config: Config) {
  const router = Router(), auth = sessionAuth(store, config), resource = `${config.publicUrl}/mcp`;
  const endpoint = (path: string) => `${config.publicUrl}${path}`;
  const metadata = {
    issuer: config.publicUrl, authorization_endpoint: endpoint('/oauth/authorize'), token_endpoint: endpoint('/oauth/token'),
    registration_endpoint: endpoint('/oauth/register'), revocation_endpoint: endpoint('/oauth/revoke'),
    response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none'], code_challenge_methods_supported: ['S256'],
    scopes_supported: [SCOPE, MANAGEMENT_SCOPE], authorization_response_iss_parameter_supported: true,
  };
  router.get('/.well-known/oauth-authorization-server', (_req, res) => res.json(metadata));
  for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
    router.get(path, (_req, res) => res.json({ resource, authorization_servers: [config.publicUrl], scopes_supported: [SCOPE, MANAGEMENT_SCOPE], bearer_methods_supported: ['header'] }));
  }
  router.post('/oauth/register', (req, res) => {
    const body = z.object({
      client_name: z.string().min(1).max(100).default('MCP client'),
      redirect_uris: z.array(z.string().max(2048)).min(1).max(5),
      token_endpoint_auth_method: z.literal('none').default('none'),
      grant_types: z.array(z.enum(['authorization_code', 'refresh_token'])).default(['authorization_code', 'refresh_token']),
      response_types: z.array(z.literal('code')).default(['code']),
    }).parse(req.body);
    if (!body.redirect_uris.every(uri => config.redirects.includes(uri))) throw new HttpError(400, 'invalid_redirect_uri');
    if ((store.db.prepare('SELECT count(*) AS n FROM clients').get() as { n: number }).n >= 1000) throw new HttpError(429, 'Client registration limit reached');
    const id = randomUUID();
    store.db.prepare('INSERT INTO clients(id,metadata,created_at) VALUES (?,?,?)').run(id, JSON.stringify(body), Date.now());
    store.audit('anonymous', 'oauth.client_registered', id);
    res.status(201).json({ ...body, client_id: id, client_id_issued_at: Math.floor(Date.now() / 1000) });
  });

  router.get('/oauth/authorize', (req, res) => {
    const args = z.object({
      response_type: z.literal('code'), client_id: z.string().uuid(), redirect_uri: z.string().max(2048),
      code_challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/), code_challenge_method: z.literal('S256'),
      state: z.string().min(1).max(1024), resource: z.literal(resource), scope: z.string().max(100).default(DEFAULT_SCOPES),
    }).parse(req.query);
    const client = store.db.prepare('SELECT metadata FROM clients WHERE id=?').get(args.client_id) as { metadata: string } | undefined;
    if (!client || !JSON.parse(client.metadata).redirect_uris.includes(args.redirect_uri) || !config.redirects.includes(args.redirect_uri))
      throw new HttpError(400, 'invalid_client_or_redirect_uri');
    const identity = auth.read(req);
    if (!identity) return res.redirect(303, `/?returnTo=${encodeURIComponent(req.originalUrl)}`);
    const requestedScopes = [...new Set(args.scope.split(/\s+/).filter(Boolean))];
    if (!requestedScopes.includes(SCOPE) || requestedScopes.some(scope => ![SCOPE, MANAGEMENT_SCOPE].includes(scope))) throw new HttpError(400, 'invalid_scope');
    args.scope = requestedScopes.filter(scope => scope !== MANAGEMENT_SCOPE || identity.user.role === 'admin').join(' ');
    const id = randomToken();
    store.db.prepare('INSERT INTO auth_requests(id,payload,user_id,expires_at) VALUES (?,?,?,?)').run(digest(id), JSON.stringify(args), identity.user.id, Date.now() + 300000);
    // The initiating document must permit the validated callback for a form POST's 303 chain.
    res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self'; style-src 'self'; form-action 'self' ${new URL(args.redirect_uri).origin}; frame-ancestors 'none'; base-uri 'none'`);
    res.type('html').send(`<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>اجازهٔ اتصال GPT</title><link rel="stylesheet" href="/style.css"><body class="consent"><main class="auth-card"><span class="eyebrow">SERVER CONNECTOR / OAUTH</span><h1>اجازهٔ اتصال GPT</h1><p>حساب: <b>${escape(identity.user.username)}</b></p><p>برنامه: <b>${escape(JSON.parse(client.metadata).client_name)}</b></p><p>دسترسی به سرورهای مجاز این حساب و نتیجهٔ کارها. دستورهای آزاد همچنان به تأیید انسانی در پنل نیاز دارند.</p>${args.scope.includes(MANAGEMENT_SCOPE) ? '<p><b>اختیار مدیریتی:</b> این اتصال می‌تواند سرورها، نقش و وضعیت حساب‌ها و مجوزهای کاربران را مدیریت کند و گزارش رخدادها را بخواند. اطلاعات ورود و کلیدهای خصوصی به GPT داده نمی‌شوند.</p>' : ''}<p>اتصال در استفادهٔ عادی خودکار تمدید می‌شود. می‌توانید آن را در پنل لغو کنید؛ تغییرات امنیتی حساب یا پایان مهلت عدم فعالیت نیازمند ورود مجدد است.</p><p class="muted">نشانی بازگشت</p><code class="break">${escape(args.redirect_uri)}</code><form method="post" action="/oauth/consent"><input type="hidden" name="request" value="${id}"><input type="hidden" name="csrf" value="${identity.csrf}"><div class="actions"><button name="decision" value="allow">اجازه می‌دهم</button><button class="secondary" name="decision" value="deny">رد اتصال</button></div></form></main></body></html>`);
  });
  router.post('/oauth/consent', auth.requireSession, auth.csrf, (req, res) => {
    const body = z.object({ request: z.string().max(100), decision: z.enum(['allow', 'deny']), csrf: z.string() }).parse(req.body);
    const row = store.db.prepare('DELETE FROM auth_requests WHERE id=? AND user_id=? AND expires_at>? RETURNING payload').get(digest(body.request), req.identity!.user.id, Date.now()) as { payload: string } | undefined;
    if (!row) throw new HttpError(400, 'Authorization request expired; restart linking');
    const args = JSON.parse(row.payload) as Authorization, callback = new URL(args.redirect_uri);
    callback.searchParams.set('state', args.state); callback.searchParams.set('iss', config.publicUrl);
    if (body.decision === 'deny') callback.searchParams.set('error', 'access_denied');
    else {
      const code = randomToken(), user = req.identity!.user;
      store.db.prepare('INSERT INTO codes(hash,user_id,client_id,redirect_uri,challenge,resource,scope,auth_version,expires_at) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(digest(code), user.id, args.client_id, args.redirect_uri, args.code_challenge, resource, args.scope, user.auth_version, Date.now() + 60000);
      callback.searchParams.set('code', code); store.audit(user.id, 'oauth.consent', args.client_id);
    }
    // Navigation is only to an exact preconfigured callback. CSP form-action permits that origin.
    res.setHeader('Content-Security-Policy', `default-src 'none'; form-action ${callback.origin}; frame-ancestors 'none'`);
    res.redirect(303, callback.toString());
  });

  function issue(userId: string, clientId: string, authVersion: number, scope: string, family: string = randomUUID()) {
    const access = randomToken(), refresh = randomToken(), now = Date.now();
    for (const [raw, kind, expiry] of [[access, 'access', now + 600000], [refresh, 'refresh', now + config.refreshIdleDays * 86400000]] as const)
      store.db.prepare('INSERT INTO tokens(hash,kind,family,user_id,client_id,resource,scope,auth_version,expires_at) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(digest(raw), kind, family, userId, clientId, resource, scope, authVersion, expiry);
    return { access_token: access, refresh_token: refresh, token_type: 'Bearer', expires_in: 600, scope };
  }

  router.post('/oauth/token', (req, res) => {
    const body = z.object({ grant_type: z.enum(['authorization_code', 'refresh_token']), client_id: z.string().uuid(), resource: z.literal(resource),
      code: z.string().max(100).optional(), redirect_uri: z.string().max(2048).optional(), code_verifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/).optional(), refresh_token: z.string().max(100).optional(),
    }).parse(req.body);
    const result = store.db.transaction(() => {
      if (body.grant_type === 'authorization_code') {
        const code = store.db.prepare('SELECT * FROM codes WHERE hash=?').get(digest(body.code || '')) as (Authorization & { user_id: string; challenge: string; auth_version: number; expires_at: number }) | undefined;
        const user = code && store.user(code.user_id);
        const challenge = createHash('sha256').update(body.code_verifier || '').digest('base64url');
        if (!code || code.client_id !== body.client_id || code.redirect_uri !== body.redirect_uri || code.resource !== body.resource || code.expires_at < Date.now() || !equal(code.challenge, challenge) || !user?.enabled || user.auth_version !== code.auth_version)
          return null;
        store.db.prepare('DELETE FROM codes WHERE hash=?').run(digest(body.code!));
        store.audit(user.id, 'oauth.token_issued', body.client_id);
        return issue(user.id, body.client_id, user.auth_version, code.scope);
      }
      const row = store.db.prepare("SELECT * FROM tokens WHERE hash=? AND kind='refresh'").get(digest(body.refresh_token || '')) as TokenRow | undefined;
      if (!row || row.client_id !== body.client_id || row.resource !== body.resource) return null;
      if (row.used) {
        store.db.prepare('UPDATE tokens SET revoked=1 WHERE family=?').run(row.family);
        store.audit(row.user_id, 'oauth.refresh_reuse', row.family); return null;
      }
      const user = store.user(row.user_id);
      if (row.revoked || row.expires_at < Date.now() || !user?.enabled || user.auth_version !== row.auth_version) return null;
      store.db.prepare('UPDATE tokens SET used=1 WHERE hash=?').run(row.hash);
      store.db.prepare("UPDATE tokens SET revoked=1 WHERE family=? AND kind='access'").run(row.family);
      return issue(user.id, row.client_id, user.auth_version, row.scope, row.family);
    })();
    if (!result) return res.status(400).json({ error: 'invalid_grant' });
    res.json(result);
  });
  router.post('/oauth/revoke', (req, res) => {
    const body = z.object({ token: z.string().max(200), client_id: z.string().uuid() }).parse(req.body);
    const row = store.db.prepare('SELECT family,user_id FROM tokens WHERE hash=? AND client_id=?').get(digest(body.token), body.client_id) as { family: string; user_id: string } | undefined;
    if (row) { store.db.prepare('UPDATE tokens SET revoked=1 WHERE family=?').run(row.family); store.audit(row.user_id, 'oauth.revoked', row.family); }
    res.sendStatus(200);
  });
  return router;
}
