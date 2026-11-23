import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { HttpError, permitted } from './auth.js';
import { Store, type Job, type Server, type User } from './db.js';
import { digest } from './security.js';
import type { Credential, Executor, ExecutionResult } from './ssh.js';
import type { Config } from './config.js';

export const diagnostics = {
  system: 'uname -srmo',
  uptime: 'uptime',
  disk: 'df -hP',
  memory: 'free -m',
  failed_services: 'SYSTEMD_PAGER=cat systemctl --no-pager --plain --failed',
} as const;
export const JobInput = z.object({
  serverId: z.string().uuid(), kind: z.enum(['diagnostic', 'command']),
  diagnostic: z.enum(['system', 'uptime', 'disk', 'memory', 'failed_services']).optional(),
  command: z.string().min(1).max(16384).refine(s => !s.includes('\0')).optional(),
  reason: z.string().min(5).max(1000), requestKey: z.string().uuid(),
}).strict();
type Payload = { command: string; reason: string; commandHash: string; result?: ExecutionResult; message?: string };

export class Jobs {
  private running = new Map<string, { controller: AbortController; task: Promise<void>; serverId: string }>();
  private interval?: ReturnType<typeof setInterval>;
  private owner = randomUUID();
  private stopped = false;
  constructor(public store: Store, public config: Config, private execute: Executor) {}

  create(user: User, input: unknown) {
    const body = JobInput.parse(input), action = body.kind === 'command' ? 'execute' : 'diagnostics';
    if (!permitted(this.store, user, body.serverId, action)) throw new HttpError(403, 'اجازهٔ این عملیات را ندارید');
    const command = body.kind === 'diagnostic' ? diagnostics[body.diagnostic!] : body.command;
    if (!command || (body.kind === 'diagnostic' && body.command) || (body.kind === 'command' && body.diagnostic)) throw new HttpError(400, 'نوع دستور معتبر نیست');
    const payload: Payload = { command, reason: body.reason, commandHash: digest(command) };
    return this.store.db.transaction(() => {
      const duplicate = this.store.db.prepare('SELECT * FROM jobs WHERE user_id=? AND request_key=?').get(user.id, body.requestKey) as Job | undefined;
      if (duplicate) {
        const previous = this.payload(duplicate);
        if (duplicate.server_id !== body.serverId || duplicate.kind !== body.kind || previous.command !== command || previous.reason !== body.reason)
          throw new HttpError(409, 'requestKey قبلاً برای درخواست دیگری استفاده شده است');
        return this.public(duplicate, user);
      }
      const count = this.store.db.prepare("SELECT count(*) AS total, sum(user_id=?) AS own FROM jobs WHERE status IN ('pending','queued','running','cancelling')").get(user.id) as { total: number; own: number };
      if (count.total >= 500 || count.own >= 50) throw new HttpError(429, 'صف کارها پر است');
      const id = randomUUID(), server = this.store.server(body.serverId)!;
      this.store.db.prepare('INSERT INTO jobs(id,user_id,server_id,server_revision,auth_version,kind,payload,status,created_at,expires_at,request_key) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
        .run(id, user.id, server.id, server.revision, user.auth_version, body.kind, this.store.vault.seal(payload, `job:${id}`), body.kind === 'command' ? 'pending' : 'queued', Date.now(), Date.now() + 900000, body.requestKey);
      this.store.audit(user.id, 'job.requested', id, { serverId: server.id, kind: body.kind, commandHash: payload.commandHash });
      return this.public(this.store.job(id)!, user);
    })();
  }
  payload(job: Job) { return this.store.vault.open<Payload>(job.payload, `job:${job.id}`); }
  private canRead(job: Job, user: User) {
    const current = this.store.user(user.id);
    if (!current?.enabled || current.auth_version !== user.auth_version) return false;
    if (current.role === 'admin') return true;
    return (user.role === 'admin' || job.user_id === user.id) && permitted(this.store, user, job.server_id, job.kind === 'command' ? 'execute' : 'diagnostics');
  }
  public(job: Job, user: User) {
    if (!this.canRead(job, user)) throw new HttpError(404, 'کار پیدا نشد');
    const { command, reason, commandHash, result, message } = this.payload(job);
    return { id: job.id, serverId: job.server_id, serverName: this.store.server(job.server_id)?.name || '', userId: job.user_id,
      username: this.store.user(job.user_id)?.username || '', kind: job.kind, command, reason, commandHash, status: job.status,
      createdAt: job.created_at, expiresAt: job.expires_at, startedAt: job.started_at, finishedAt: job.finished_at,
      approvedBy: job.approved_by, result: result || null, message: message || null };
  }
  list(user: User) {
    const rows = this.store.db.prepare(user.role === 'admin' ? 'SELECT * FROM jobs ORDER BY created_at DESC LIMIT 100' : 'SELECT * FROM jobs WHERE user_id=? ORDER BY created_at DESC LIMIT 100')
      .all(...(user.role === 'admin' ? [] : [user.id])) as Job[];
    return rows.filter(row => this.canRead(row, user)).map(row => this.public(row, user));
  }
  get(user: User, id: string) { const row = this.store.job(id); if (!row) throw new HttpError(404, 'کار پیدا نشد'); return this.public(row, user); }
  approve(admin: User, id: string, commandHash: string) {
    const current = this.store.user(admin.id);
    if (current?.role !== 'admin' || !current.enabled || current.auth_version !== admin.auth_version) throw new HttpError(403, 'دسترسی مدیر لازم است');
    this.store.db.transaction(() => {
      const job = this.store.job(id);
      if (!job || job.status !== 'pending' || job.expires_at <= Date.now()) throw new HttpError(409, 'کار در انتظار تأیید نیست یا منقضی شده است');
      if (!this.authorized(job)) throw new HttpError(409, 'مجوز یا تنظیمات سرور تغییر کرده است');
      if (this.payload(job).commandHash !== commandHash) throw new HttpError(409, 'متن دستور تغییر کرده است');
      this.store.db.prepare("UPDATE jobs SET status='queued',approved_by=?,approver_version=? WHERE id=? AND status='pending'").run(admin.id, admin.auth_version, id);
      this.store.audit(admin.id, 'job.approved', id, { commandHash });
    })();
    return this.get(admin, id);
  }
  cancel(user: User, id: string, reject = false) {
    const job = this.store.job(id); if (!job) throw new HttpError(404, 'کار پیدا نشد');
    this.public(job, user);
    if (!['pending', 'queued', 'running', 'cancelling'].includes(job.status)) throw new HttpError(409, 'کار پایان یافته است');
    const status = job.status === 'running' || job.status === 'cancelling' ? 'cancelling' : reject ? 'rejected' : 'cancelled';
    this.store.db.prepare('UPDATE jobs SET status=?,finished_at=? WHERE id=?').run(status, status === 'cancelling' ? null : Date.now(), id);
    this.running.get(id)?.controller.abort(); this.store.audit(user.id, reject ? 'job.rejected' : 'job.cancelled', id);
    return this.get(user, id);
  }
  private authorized(job: Job) {
    const user = this.store.user(job.user_id), server = this.store.server(job.server_id);
    if (!user || user.auth_version !== job.auth_version || !server || server.revision !== job.server_revision || !permitted(this.store, user, server.id, job.kind === 'command' ? 'execute' : 'diagnostics')) return false;
    if (job.kind === 'command' && job.status !== 'pending') {
      const admin = job.approved_by && this.store.user(job.approved_by);
      if (!admin || !admin.enabled || admin.role !== 'admin' || admin.auth_version !== job.approver_version) return false;
    }
    return true;
  }
  start() {
    this.store.db.transaction(() => {
      const now = Date.now();
      const lock = this.store.db.prepare('SELECT owner,expires_at FROM runtime_lock WHERE id=1').get() as { owner: string; expires_at: number } | undefined;
      if (lock && lock.expires_at > now) throw new Error('Another gateway worker is active; run exactly one replica');
      this.store.db.prepare('INSERT INTO runtime_lock(id,owner,expires_at) VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at').run(this.owner, now + 10000);
      this.store.db.prepare("UPDATE jobs SET status='interrupted',finished_at=? WHERE status IN ('running','cancelling')").run(now);
      this.store.audit('system', 'worker.started');
    })();
    this.interval = setInterval(() => this.tick(), 500); this.interval.unref(); this.tick();
  }
  healthy() {
    const row = this.store.db.prepare('SELECT owner,expires_at FROM runtime_lock WHERE id=1').get() as { owner: string; expires_at: number } | undefined;
    return !this.stopped && !!this.interval && row?.owner === this.owner && row.expires_at > Date.now();
  }
  tick() {
    if (this.stopped) return;
    const now = Date.now();
    const lock = this.store.db.prepare('UPDATE runtime_lock SET expires_at=? WHERE id=1 AND owner=? AND expires_at>?').run(now + 10000, this.owner, now);
    if (!lock.changes) { this.stopped = true; for (const task of this.running.values()) task.controller.abort(); return; }
    for (const [id, running] of this.running) {
      const job = this.store.job(id)!;
      if (job.status === 'cancelling' || !this.authorized(job)) running.controller.abort();
    }
    this.store.db.prepare("UPDATE jobs SET status='expired',finished_at=? WHERE status IN ('pending','queued') AND expires_at<=?").run(now, now);
    const queued = this.store.db.prepare("SELECT * FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 500").all() as Job[];
    for (const job of queued) {
      if (this.running.size >= this.config.concurrency) break;
      if ([...this.running.values()].some(r => r.serverId === job.server_id)) continue;
      if (!this.authorized(job)) {
        this.store.db.prepare("UPDATE jobs SET status='cancelled',finished_at=? WHERE id=?").run(now, job.id);
        this.store.audit('system', 'job.authorization_changed', job.id); continue;
      }
      if (!this.store.db.prepare("UPDATE jobs SET status='running',started_at=? WHERE id=? AND status='queued'").run(now, job.id).changes) continue;
      const controller = new AbortController();
      const task = this.run(job, controller.signal).finally(() => this.running.delete(job.id));
      this.running.set(job.id, { controller, task, serverId: job.server_id });
    }
  }
  private async run(job: Job, signal: AbortSignal) {
    const payload = this.payload(job);
    try {
      this.store.audit(job.user_id, 'job.started', job.id, { commandHash: payload.commandHash });
      const server = this.store.server(job.server_id)!;
      const credential = this.store.vault.open<Credential>(server.credential, `server:${server.id}`);
      payload.result = await this.execute(server, credential, payload.command, signal);
    } catch {
      payload.message = 'Execution failed; remote state is unknown. Review before retrying.';
      payload.result = { stdout: '', stderr: '', exitCode: null, signal: null, outcome: 'connection_error', remoteState: 'unknown', truncated: false };
    }
    const current = this.store.job(job.id)!;
    const status = signal.aborted || current.status === 'cancelling' ? 'cancelled' : payload.result.outcome === 'completed' ? payload.result.exitCode === 0 ? 'succeeded' : 'failed' : payload.result.outcome;
    this.store.db.prepare('UPDATE jobs SET payload=?,status=?,finished_at=? WHERE id=?').run(this.store.vault.seal(payload, `job:${job.id}`), status, Date.now(), job.id);
    this.store.audit(job.user_id, 'job.finished', job.id, { status, exitCode: payload.result.exitCode, remoteState: payload.result.remoteState, truncated: payload.result.truncated });
  }
  maintenance() {
    const now = Date.now(), cutoff = now - this.config.retentionDays * 86400000;
    this.store.db.transaction(() => {
      this.store.db.prepare("DELETE FROM jobs WHERE finished_at<? AND status NOT IN ('running','cancelling')").run(cutoff);
      this.store.db.prepare('DELETE FROM sessions WHERE expires_at<?').run(now);
      this.store.db.prepare('DELETE FROM codes WHERE expires_at<?').run(now);
      this.store.db.prepare('DELETE FROM auth_requests WHERE expires_at<?').run(now);
      // Keep used refresh tokens while a live family exists, so replay still revokes that family.
      this.store.db.prepare('DELETE FROM tokens WHERE family IN (SELECT family FROM tokens GROUP BY family HAVING max(expires_at)<?)').run(now);
      this.store.db.prepare('DELETE FROM login_failures WHERE reset_at<?').run(now);
    })();
  }
  async stop() {
    this.stopped = true; clearInterval(this.interval);
    for (const running of this.running.values()) running.controller.abort();
    await Promise.allSettled([...this.running.values()].map(r => r.task));
    this.store.db.prepare('DELETE FROM runtime_lock WHERE id=1 AND owner=?').run(this.owner);
  }
}
