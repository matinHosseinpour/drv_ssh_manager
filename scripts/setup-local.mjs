import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const value = `NODE_ENV=development\nPUBLIC_URL=http://localhost:3080\nLISTEN_HOST=127.0.0.1\nPORT=3080\nDATABASE_PATH=./data/connector.sqlite\nMASTER_KEY=${randomBytes(32).toString('base64')}\nSSH_ALLOWED_CIDRS=10.20.0.0/24\nOAUTH_REDIRECT_URIS=https://chatgpt.com/connector_platform_oauth_redirect\nREQUIRE_MFA=true\n`;
try { writeFileSync('.env', value, { flag: 'wx', mode: 0o600 }); console.log('Created .env with a private random key. Edit SSH_ALLOWED_CIDRS before adding targets.'); }
catch (error) { console.error(error.code === 'EEXIST' ? '.env already exists; no changes made.' : 'Could not create .env'); process.exitCode = 1; }
