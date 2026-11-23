import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, copyFileSync, constants, chmodSync } from 'node:fs';
mkdirSync('secrets', { recursive: true, mode: 0o700 }); chmodSync('secrets', 0o700);
try {
  // Compose file-backed secrets preserve the source mode. The enclosing host directory is 0700;
  // only the single file is mounted, read-only, for the non-root container user.
  writeFileSync('secrets/master_key', `${randomBytes(32).toString('base64')}\n`, { flag: 'wx', mode: 0o644 });
  console.log('Created a master key under the private secrets directory. Back it up separately.');
} catch (error) { if (error.code !== 'EEXIST') throw error; console.log('Existing master key preserved.'); }
try { copyFileSync('deploy/production.env.example', '.env', constants.COPYFILE_EXCL); chmodSync('.env', 0o600); console.log('Created .env. Set the real domain, email, target CIDRs and exact OAuth callback.'); }
catch (error) { if (error.code !== 'EEXIST') throw error; console.log('Existing .env preserved.'); }
