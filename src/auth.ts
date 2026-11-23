import type { Request, Response, NextFunction } from 'express';
import type { Config } from './config.js';
import { Store, type User } from './db.js';
import { digest, equal, matchTotp, randomToken, verifyPassword } from './security.js';

export class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}
export type Identity = { user: User; csrf: string; sessionHash: string };
declare global { namespace Express { interface Request { identity?: Identity } } }

export function sessionAuth(store: Store, config: Config) {
  const cookieName = config.production ? '__Host-connector' : 'connector_session';
  const cookieOptions = { httpOnly: true, secure: config.production, sameSite: 'lax' as const, path: '/' };
  function read(req: Request) {
    const raw = req.cookies?.[cookieName];
    if (typeof raw !== 'string' || raw.length > 100) return undefined;
    const hash = digest(raw);
    const session = store.db.prepare('SELECT * FROM sessions WHERE hash=? AND expires_at>?').get(hash, Date.now()) as { user_id: string; auth_version: number; csrf: string } | undefined;
    const user = session && store.user(session.user_id);
    if (!session || !user?.enabled || user.auth_version !== session.auth_version) return undefined;
    return { user, csrf: session.csrf, sessionHash: hash };
  }
  function requireSession(req: Request, _res: Response, next: NextFunction) {
    const identity = read(req);
    if (!identity) throw new HttpError(401, 'ابتدا وارد حساب شوید');
    req.identity = identity; next();
  }
  function csrf(req: Request, _res: Response, next: NextFunction) {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      const value = req.get('x-csrf-token') || req.body?.csrf;
      if (req.get('origin') !== config.publicUrl || !req.identity || typeof value !== 'string' || !equal(value, req.identity.csrf))
        throw new HttpError(403, 'درخواست نامعتبر است؛ صفحه را تازه کنید');
    }
    next();
  }
  function checkAdmin(req: Request) {
    const initial = req.identity?.user, current = initial && store.user(initial.id);
    if (!current?.enabled || current.role !== 'admin' || current.auth_version !== initial?.auth_version) throw new HttpError(403, 'دسترسی مدیر لازم است');
  }
  function admin(req: Request, _res: Response, next: NextFunction) {
    checkAdmin(req); next();
  }
  async function login(username: string, password: string, otp: string, dummyHash: string) {
    const key = digest(username);
    store.db.prepare('DELETE FROM login_failures WHERE reset_at<?').run(Date.now());
    const locked = store.db.prepare('SELECT count FROM login_failures WHERE key=?').get(key) as { count: number } | undefined;
    if (locked && locked.count >= 8) throw new HttpError(429, 'تلاش‌های ورود زیاد است؛ ۱۵ دقیقه بعد دوباره امتحان کنید');
    const user = store.db.prepare('SELECT * FROM users WHERE username=?').get(username) as User | undefined;
    const passwordOk = await verifyPassword(password, user?.password_hash || dummyHash);
    let step: number | null = null;
    if (user?.totp_cipher) step = matchTotp(store.vault.open<string>(user.totp_cipher, `totp:${user.id}`), otp, user.last_totp_step);
    if (!user?.enabled || !passwordOk || (user.totp_cipher && step === null) || (config.requireMfa && !user.totp_cipher)) {
      store.db.prepare('INSERT INTO login_failures(key,count,reset_at) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1').run(key, Date.now() + 900000);
      store.audit(user?.id || 'anonymous', 'login.failed');
      throw new HttpError(401, 'نام کاربری، رمز یا کد یک‌بارمصرف معتبر نیست');
    }
    // Consume TOTP atomically after asynchronous password verification.
    if (step !== null && !store.db.prepare('UPDATE users SET last_totp_step=? WHERE id=? AND last_totp_step<? AND enabled=1 AND auth_version=?').run(step, user.id, step, user.auth_version).changes)
      throw new HttpError(401, 'کد یک‌بارمصرف قبلاً استفاده شده است');
    const current = store.user(user.id);
    if (!current?.enabled || current.auth_version !== user.auth_version) throw new HttpError(401, 'حساب تغییر کرده است؛ دوباره وارد شوید');
    store.db.prepare('DELETE FROM login_failures WHERE key=?').run(key);
    const token = randomToken(), csrf = randomToken();
    store.db.prepare('INSERT INTO sessions(hash,user_id,csrf,auth_version,expires_at) VALUES (?,?,?,?,?)').run(digest(token), user.id, csrf, user.auth_version, Date.now() + 8 * 3600000);
    store.audit(user.id, 'login.succeeded');
    return { token, csrf, user };
  }
  return { read, requireSession, csrf, admin, checkAdmin, login, cookieName, cookieOptions };
}

export function permitted(store: Store, user: User, serverId: string, action: 'diagnostics' | 'execute') {
  const current = store.user(user.id), server = store.server(serverId);
  if (!current?.enabled || current.auth_version !== user.auth_version || !server?.enabled) return false;
  if (action === 'execute' && current.role === 'viewer') return false;
  if (current.role === 'admin') return true;
  const grant = store.db.prepare(`SELECT ${action} AS allowed FROM grants WHERE user_id=? AND server_id=?`).get(user.id, serverId) as { allowed: number } | undefined;
  return !!grant?.allowed;
}
