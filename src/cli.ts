import { randomUUID } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { existsSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadConfig } from './config.js';
import { Store, type User } from './db.js';
import { hashPassword, newTotpSecret } from './security.js';

const config = loadConfig(), store = new Store(config.databasePath, config.masterKey);
const [action, username] = process.argv.slice(2);
async function hidden(prompt: string) {
  if (!stdin.isTTY || !stdout.isTTY) throw new Error('Use an interactive terminal for credentials');
  return new Promise<string>((resolve, reject) => {
    let value = '';
    const onData = (data: Buffer) => {
      for (const char of data.toString()) {
        if (char === '\u0003') { cleanup(); reject(new Error('Cancelled')); return; }
        if (char === '\r' || char === '\n') { cleanup(); stdout.write('\n'); resolve(value); return; }
        if (char === '\u007f') value = value.slice(0, -1); else if (char >= ' ') value += char;
      }
    };
    const cleanup = () => { stdin.off('data', onData); stdin.setRawMode(false); stdin.pause(); };
    // Disable terminal echo before displaying the prompt, including fast pasted input.
    stdin.setRawMode(true); stdin.on('data', onData); stdin.resume(); stdout.write(prompt);
  });
}
try {
  if (action === 'has-admin') {
    const row = store.db.prepare("SELECT count(*) AS n FROM users WHERE enabled=1 AND role='admin' AND totp_cipher IS NOT NULL").get() as { n: number };
    console.log(row.n ? 'Administrator already configured.' : 'No active MFA administrator.');
    process.exitCode = row.n ? 0 : 3;
  }
  else if (action === 'backup') {
    if (!username) throw new Error('Provide a new destination path for the database backup');
    const destination = resolve(username);
    if (existsSync(destination)) throw new Error('Backup destination already exists; no changes made');
    await store.db.backup(destination); chmodSync(destination, 0o600);
    store.audit('local-cli', 'database.backup'); console.log('Encrypted database backup created; keep the master key separately.');
  }
  else if (action === 'verify-audit') console.log(JSON.stringify(store.verifyAudit(), null, 2));
  else if (action === 'checkpoint') console.log(JSON.stringify(store.verifyAudit()));
  else if (['create-admin', 'reset-account'].includes(action || '')) {
    if (!username || !/^[a-zA-Z0-9_.@-]{3,80}$/.test(username)) throw new Error('Provide a valid username');
    const existing = store.db.prepare('SELECT * FROM users WHERE username=?').get(username) as User | undefined;
    if (action === 'create-admin' && existing) throw new Error('Account already exists');
    if (action === 'reset-account' && !existing) throw new Error('Account not found');
    const password = await hidden('Password (14+ characters, hidden): '), confirmation = await hidden('Repeat password: ');
    if (password !== confirmation) throw new Error('Passwords do not match');
    const hash = await hashPassword(password), id = existing?.id || randomUUID(), secret = newTotpSecret();
    stdout.write(`Add this MFA setup key to your authenticator now (shown once): ${secret}\n`);
    const rl = createInterface({ input: stdin, output: stdout });
    const answer = await rl.question('Enter the current 6-digit code to confirm enrollment: '); rl.close();
    const { matchTotp } = await import('./security.js');
    const step = matchTotp(secret, answer.trim(), -1);
    if (step === null) throw new Error('Invalid MFA code; account was not changed');
    store.db.transaction(() => {
      if (existing) store.db.prepare('UPDATE users SET password_hash=?,totp_cipher=?,last_totp_step=?,enabled=1,auth_version=auth_version+1 WHERE id=?').run(hash, store.vault.seal(secret, `totp:${id}`), step, id);
      else store.db.prepare('INSERT INTO users(id,username,password_hash,role,totp_cipher,last_totp_step,created_at) VALUES (?,?,?,?,?,?,?)').run(id, username, hash, 'admin', store.vault.seal(secret, `totp:${id}`), step, Date.now());
      store.audit('local-cli', existing ? 'account.recovered' : 'account.created', id);
    })();
    console.log('Account saved. Wait for a fresh MFA code before logging in.');
  } else throw new Error('Usage: npm run admin -- create-admin USER | reset-account USER | has-admin | verify-audit | checkpoint | backup NEW_PATH');
} catch (error) { console.error(error instanceof Error ? error.message : 'Command failed'); process.exitCode = 1; }
finally { store.close(); }
