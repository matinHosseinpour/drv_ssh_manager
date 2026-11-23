import 'dotenv/config';
import { readFileSync } from 'node:fs';
import { z } from 'zod';
import ipaddr from 'ipaddr.js';

export type Config = ReturnType<typeof loadConfig>;
export function loadConfig(env: NodeJS.ProcessEnv = process.env) {
  const production = env.NODE_ENV === 'production';
  const publicUrl = new URL(env.PUBLIC_URL || 'http://localhost:3080');
  if (publicUrl.pathname !== '/' || publicUrl.search || publicUrl.hash || publicUrl.username || publicUrl.password)
    throw new Error('PUBLIC_URL must be an origin without a path or credentials');
  if (publicUrl.protocol !== 'https:' && !(publicUrl.protocol === 'http:' && !production && ['localhost', '127.0.0.1', '[::1]'].includes(publicUrl.hostname)))
    throw new Error('PUBLIC_URL must use HTTPS (loopback HTTP is development only)');
  const encodedKey = env.MASTER_KEY_FILE ? readFileSync(env.MASTER_KEY_FILE, 'utf8').trim() : env.MASTER_KEY || '';
  if (!/^[A-Za-z0-9+/]{43}=$/.test(encodedKey) || Buffer.from(encodedKey, 'base64').length !== 32)
    throw new Error('Configure a random 32-byte base64 MASTER_KEY or MASTER_KEY_FILE');
  const cidrs = (env.SSH_ALLOWED_CIDRS || '').split(',').map(v => v.trim()).filter(Boolean);
  if (!cidrs.length) throw new Error('SSH_ALLOWED_CIDRS must explicitly allow target networks');
  const networks = cidrs.map(v => ipaddr.parseCIDR(v));
  if (networks.some(([, prefix]) => prefix === 0)) throw new Error('Default-route SSH allowlists are forbidden');
  const redirects = (env.OAUTH_REDIRECT_URIS || 'https://chatgpt.com/connector_platform_oauth_redirect').split(',').map(s => s.trim());
  for (const value of redirects) {
    const uri = new URL(value);
    if (uri.hash || uri.username || uri.password || (uri.protocol !== 'https:' && !(uri.protocol === 'http:' && !production && ['localhost', '127.0.0.1'].includes(uri.hostname))))
      throw new Error('OAuth callbacks must be exact HTTPS URLs');
  }
  const requireMfa = env.REQUIRE_MFA !== 'false';
  if (production && !requireMfa) throw new Error('MFA is required in production');
  const trustedProxies = (env.TRUSTED_PROXY_CIDRS || '').split(',').map(v => v.trim()).filter(Boolean);
  for (const cidr of trustedProxies) { if (ipaddr.parseCIDR(cidr)[1] === 0) throw new Error('Do not trust all proxies'); }
  const integer = (key: string, fallback: number, max: number) => z.coerce.number().int().min(1).max(max).parse(env[key] || fallback);
  return {
    production, publicUrl: publicUrl.origin, masterKey: Buffer.from(encodedKey, 'base64'), networks,
    redirects, requireMfa, trustedProxies, host: env.LISTEN_HOST || '127.0.0.1',
    port: integer('PORT', 3080, 65535), databasePath: env.DATABASE_PATH || './data/connector.sqlite',
    concurrency: integer('MAX_CONCURRENT_JOBS', 4, 16), timeout: integer('JOB_TIMEOUT_SECONDS', 60, 120),
    outputLimit: integer('OUTPUT_LIMIT_BYTES', 65536, 262144), retentionDays: integer('RETENTION_DAYS', 30, 365),
    refreshIdleDays: integer('OAUTH_REFRESH_IDLE_DAYS', 90, 365),
  };
}

export function checkTarget(config: Config, value: string) {
  if (!ipaddr.isValid(value) || value.includes('%')) throw new Error('Use a literal IP address; hostnames and zone IDs are forbidden');
  let address = ipaddr.parse(value);
  if (address.kind() === 'ipv6' && (address as ipaddr.IPv6).isIPv4MappedAddress())
    throw new Error('IPv4-mapped IPv6 addresses are forbidden');
  if (['unspecified', 'broadcast', 'multicast', 'linkLocal'].includes(address.range()))
    throw new Error('This target address is forbidden');
  if (!config.networks.some(([network, prefix]) => network.kind() === address.kind() && address.match(network, prefix)))
    throw new Error('Target is outside SSH_ALLOWED_CIDRS');
  return address.toString();
}
