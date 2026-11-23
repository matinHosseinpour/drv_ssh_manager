import Database from 'better-sqlite3';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Vault } from './security.js';

export type User = { id: string; username: string; password_hash: string; role: 'admin' | 'operator' | 'viewer'; enabled: number; auth_version: number; totp_cipher: string | null; last_totp_step: number; created_at: number };
export type Server = { id: string; name: string; address: string; port: number; username: string; fingerprint: string; credential: string; enabled: number; revision: number; created_at: number };
export type Job = { id: string; user_id: string; server_id: string; server_revision: number; auth_version: number; kind: string; payload: string; status: string; approved_by: string | null; approver_version: number | null; created_at: number; expires_at: number; started_at: number | null; finished_at: number | null; request_key: string };

export class Store {
  db: Database.Database;
  vault: Vault;
  constructor(path: string, key: Buffer) {
    process.umask(0o077);
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new Database(path);
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.db.pragma('journal_mode = WAL'); this.db.pragma('foreign_keys = ON'); this.db.pragma('synchronous = FULL'); this.db.pragma('busy_timeout = 5000');
    this.vault = new Vault(key);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')), enabled INTEGER NOT NULL DEFAULT 1, auth_version INTEGER NOT NULL DEFAULT 1, totp_cipher TEXT, last_totp_step INTEGER NOT NULL DEFAULT -1, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), csrf TEXT NOT NULL, auth_version INTEGER NOT NULL, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS login_failures (key TEXT PRIMARY KEY, count INTEGER NOT NULL, reset_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS servers (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL, username TEXT NOT NULL, fingerprint TEXT NOT NULL, credential TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS grants (user_id TEXT NOT NULL REFERENCES users(id), server_id TEXT NOT NULL REFERENCES servers(id), diagnostics INTEGER NOT NULL, execute INTEGER NOT NULL, PRIMARY KEY(user_id,server_id));
      CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, metadata TEXT NOT NULL, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS auth_requests (id TEXT PRIMARY KEY, payload TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id), expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS codes (hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), client_id TEXT NOT NULL REFERENCES clients(id), redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, resource TEXT NOT NULL, scope TEXT NOT NULL, auth_version INTEGER NOT NULL, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, kind TEXT NOT NULL, family TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id), client_id TEXT NOT NULL REFERENCES clients(id), resource TEXT NOT NULL, scope TEXT NOT NULL, auth_version INTEGER NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0);
      CREATE INDEX IF NOT EXISTS token_family ON tokens(family);
      CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), server_id TEXT NOT NULL REFERENCES servers(id), server_revision INTEGER NOT NULL, auth_version INTEGER NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL, approved_by TEXT REFERENCES users(id), approver_version INTEGER, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER, request_key TEXT NOT NULL, UNIQUE(user_id,request_key));
      CREATE INDEX IF NOT EXISTS job_status ON jobs(status,created_at);
      CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL, detail TEXT NOT NULL, previous TEXT NOT NULL, mac TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS runtime_lock (id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, expires_at INTEGER NOT NULL);
      PRAGMA user_version = 1;
    `);
  }
  user(id: string) { return this.db.prepare('SELECT * FROM users WHERE id=?').get(id) as User | undefined; }
  server(id: string) { return this.db.prepare('SELECT * FROM servers WHERE id=?').get(id) as Server | undefined; }
  job(id: string) { return this.db.prepare('SELECT * FROM jobs WHERE id=?').get(id) as Job | undefined; }
  audit(actor: string, action: string, resource = '', detail: Record<string, unknown> = {}) {
    this.db.transaction(() => {
      const previous = (this.db.prepare('SELECT mac FROM audit ORDER BY seq DESC LIMIT 1').get() as { mac: string } | undefined)?.mac || 'genesis';
      const row = { id: randomUUID(), at: Date.now(), actor, action, resource, detail: JSON.stringify(detail), previous };
      const mac = this.vault.sign(JSON.stringify(row));
      this.db.prepare('INSERT INTO audit(id,at,actor,action,resource,detail,previous,mac) VALUES (@id,@at,@actor,@action,@resource,@detail,@previous,@mac)').run({ ...row, mac });
    })();
  }
  verifyAudit() {
    let previous = 'genesis'; let count = 0;
    for (const raw of this.db.prepare('SELECT * FROM audit ORDER BY seq').iterate()) {
      const { seq: _seq, mac, ...row } = raw as Record<string, any>;
      if (row.previous !== previous || this.vault.sign(JSON.stringify(row)) !== mac) return { valid: false, checked: count };
      previous = mac; count++;
    }
    return { valid: true, checked: count, checkpoint: previous };
  }
  close() { this.db.close(); }
}
