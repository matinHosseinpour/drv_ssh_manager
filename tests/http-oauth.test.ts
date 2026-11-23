import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { fixture, grant, target, user } from './helpers.js';
import { digest, newTotpSecret, totp } from '../src/security.js';

async function authorize(f: Awaited<ReturnType<typeof fixture>>, account: Awaited<ReturnType<typeof user>>) {
  const session = await f.login(account), verifier = 'v'.repeat(64), challenge = createHash('sha256').update(verifier).digest('base64url');
  const callback = f.config.redirects[0]!;
  const registration = await f.request('/oauth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_name: 'Integration test', redirect_uris: [callback], token_endpoint_auth_method: 'none' }) });
  assert.equal(registration.status, 201); const client = await registration.json() as { client_id: string };
  const params = new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: callback, code_challenge: challenge, code_challenge_method: 'S256', state: 'state-123', resource: `${f.config.publicUrl}/mcp`, scope: 'servers:access' });
  const consent = await f.request(`/oauth/authorize?${params}`, { headers: { Cookie: session.cookie } });
  assert.equal(consent.status, 200); assert(consent.headers.get('content-security-policy')!.includes(new URL(callback).origin));
  const html = await consent.text(), requestId = html.match(/name="request" value="([^"]+)"/)![1]!;
  const response = await f.request('/oauth/consent', { method: 'POST', headers: { Cookie: session.cookie, Origin: f.config.publicUrl, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ request: requestId, decision: 'allow', csrf: session.csrf }) });
  assert.equal(response.status, 303);
  const redirect = new URL(response.headers.get('location')!); assert.equal(redirect.searchParams.get('state'), 'state-123'); assert.equal(redirect.searchParams.get('iss'), f.config.publicUrl);
  return { ...session, clientId: client.client_id, verifier, code: redirect.searchParams.get('code')!, callback, params };
}
const tokenRequest = (f: Awaited<ReturnType<typeof fixture>>, body: object) => f.request('/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ ...body, resource: `${f.config.publicUrl}/mcp` } as Record<string, string>) });

test('HTTP rejects unauthenticated, forged Host, foreign Origin, CSRF and bearer-only approvals', async () => {
  const f = await fixture();
  try {
    const admin = await user(f.store, 'admin', 'http-admin'), session = await f.login(admin);
    assert.equal((await f.request('/api/servers')).status, 401);
    const forgedHostStatus = await new Promise<number>(resolve => { const request = httpRequest(`${f.config.publicUrl}/healthz`, { headers: { Host: 'evil.example' } }, response => { response.resume(); resolve(response.statusCode!); }); request.end(); });
    assert.equal(forgedHostStatus, 421);
    assert.equal((await f.request('/api/session', { headers: { Origin: 'https://evil.example' } })).status, 403);
    assert.equal((await f.request('/api/logout', { method: 'POST', headers: { Cookie: session.cookie, Origin: f.config.publicUrl, 'Content-Type': 'application/json' }, body: '{}' })).status, 403);
    const mcp = await f.request('/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(mcp.status, 401); assert(mcp.headers.get('www-authenticate')!.includes('/.well-known/oauth-protected-resource/mcp'));
    const protectedApi = await f.request(`/api/jobs/${randomUUID()}/approve`, { method: 'POST', headers: { Authorization: 'Bearer invalid', Origin: f.config.publicUrl, 'Content-Type': 'application/json' }, body: '{}' }); assert.equal(protectedApi.status, 401);
    const discovery = await (await f.request('/.well-known/oauth-authorization-server')).json() as any;
    assert.deepEqual(discovery.code_challenge_methods_supported, ['S256']); assert.equal(discovery.authorization_response_iss_parameter_supported, true);
    assert.equal((await f.request('/healthz')).status, 200);
    const localAddress = f.config.publicUrl;
    f.config.publicUrl = 'https://gateway.example.com';
    const privateHealth = await new Promise<number>(resolve => { const request = httpRequest(`${localAddress}/healthz`, { headers: { Host: 'gateway.example.com' } }, response => { response.resume(); resolve(response.statusCode!); }); request.end(); });
    assert.equal(privateHealth, 200);
  } finally { await f.close(); }
});

test('OAuth code exchange, audience binding, PKCE, refresh rotation/reuse and SDK MCP calls', async () => {
  const f = await fixture();
  try {
    const operator = await user(f.store, 'operator', 'oauth-operator'), server = target(f.store); grant(f.store, operator.id, server.id);
    const auth = await authorize(f, operator);
    const exchange = { grant_type: 'authorization_code', client_id: auth.clientId, code: auth.code, redirect_uri: auth.callback, code_verifier: auth.verifier };
    assert.equal((await tokenRequest(f, { ...exchange, code_verifier: 'x'.repeat(64) })).status, 400);
    const wrongAudience = await f.request('/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...exchange, resource: 'https://evil.example/mcp' }) }); assert.equal(wrongAudience.status, 400);
    const tokenResponse = await tokenRequest(f, exchange); assert.equal(tokenResponse.status, 200); assert.equal(tokenResponse.headers.get('cache-control'), 'no-store');
    const tokens = await tokenResponse.json() as { access_token: string; refresh_token: string };
    assert.equal((await tokenRequest(f, exchange)).status, 400);
    assert(!JSON.stringify(f.store.db.prepare('SELECT * FROM tokens').all()).includes(tokens.access_token));
    const transport = new StreamableHTTPClientTransport(new URL(`${f.config.publicUrl}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${tokens.access_token}` } } });
    const client = new Client({ name: 'test-client', version: '1.0.0' }); await client.connect(transport);
    try {
      const tools = await client.listTools(); assert.equal(tools.tools.length, 10); assert(!tools.tools.some(tool => /approve/.test(tool.name))); assert(!tools.tools.some(tool => tool.name === 'list_users'));
      const listed = await client.callTool({ name: 'list_servers', arguments: {} }); assert(!JSON.stringify(listed).includes('127.0.0.1')); assert(JSON.stringify(listed).includes(server.name));
      const request = await client.callTool({ name: 'request_command', arguments: { serverId: server.id, command: 'echo hello', reason: 'test human approval', requestKey: randomUUID() } });
      assert(JSON.stringify(request).includes('pending')); assert.equal(f.store.db.prepare("SELECT count(*) AS n FROM jobs WHERE status='pending'").get()!.n, 1);
    } finally { await client.close(); }
    const refresh = await tokenRequest(f, { grant_type: 'refresh_token', client_id: auth.clientId, refresh_token: tokens.refresh_token }); assert.equal(refresh.status, 200);
    const rotated = await refresh.json() as { access_token: string; refresh_token: string }; assert.notEqual(rotated.refresh_token, tokens.refresh_token);
    const probe = (access: string) => f.request('/mcp', { method: 'POST', headers: { Authorization: `Bearer ${access}`, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal((await probe(tokens.access_token)).status, 401);
    assert.equal((await tokenRequest(f, { grant_type: 'refresh_token', client_id: auth.clientId, refresh_token: tokens.refresh_token })).status, 400);
    assert.equal((await probe(rotated.access_token)).status, 401);
    assert(f.store.verifyAudit().valid);
  } finally { await f.close(); }
});

test('OAuth exact redirect allowlist, consent CSRF and user disable are enforced', async () => {
  const f = await fixture();
  try {
    const invalid = await f.request('/oauth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ redirect_uris: ['https://chatgpt.com.evil.example/callback'] }) }); assert.equal(invalid.status, 400);
    const account = await user(f.store, 'admin', 'revocation-admin'), auth = await authorize(f, account);
    const exchange = { grant_type: 'authorization_code', client_id: auth.clientId, code: auth.code, redirect_uri: auth.callback, code_verifier: auth.verifier };
    const response = await tokenRequest(f, exchange), tokens = await response.json() as any;
    f.store.db.prepare('UPDATE users SET enabled=0 WHERE id=?').run(account.id);
    const session = await (await f.request('/api/session', { headers: { Cookie: auth.cookie } })).json() as any; assert.equal(session.user, null);
    assert.equal((await f.request('/mcp', { method: 'POST', headers: { Authorization: `Bearer ${tokens.access_token}`, 'Content-Type': 'application/json' }, body: '{}' })).status, 401);
    assert.equal((await tokenRequest(f, { grant_type: 'refresh_token', client_id: auth.clientId, refresh_token: tokens.refresh_token })).status, 400);
  } finally { await f.close(); }
});

test('admin API preserves secrets, requires revisions and protects the last administrator', async () => {
  const f = await fixture();
  try {
    const admin = await user(f.store, 'admin', 'api-admin'), operator = await user(f.store, 'operator', 'api-operator'), session = await f.login(admin);
    const headers = { Cookie: session.cookie, Origin: f.config.publicUrl, 'X-CSRF-Token': session.csrf, 'Content-Type': 'application/json' };
    const body = { name: 'server-via-api', address: '10.20.0.5', port: 22, username: 'gptops', fingerprint: `SHA256:${'A'.repeat(43)}`, credential: { type: 'password', password: 'never-return-this-secret' } };
    const response = await f.request('/api/admin/servers', { method: 'POST', headers, body: JSON.stringify(body) }); assert.equal(response.status, 201); const { id } = await response.json() as any;
    const listed = await (await f.request('/api/servers', { headers })).text(); assert(!listed.includes('never-return-this-secret')); assert(!listed.includes('credential"'));
    const root = await f.request('/api/admin/servers', { method: 'POST', headers, body: JSON.stringify({ ...body, name: 'bad-root', username: 'root' }) }); assert.equal(root.status, 400);
    assert.equal((await f.request(`/api/admin/servers/${id}`, { method: 'PATCH', headers, body: JSON.stringify({ enabled: false, revision: 1 }) })).status, 200);
    assert.equal((await f.request(`/api/admin/servers/${id}`, { method: 'PATCH', headers, body: JSON.stringify({ enabled: true, revision: 1 }) })).status, 409);
    assert.equal((await f.request(`/api/admin/users/${admin.id}`, { method: 'PATCH', headers, body: JSON.stringify({ enabled: false }) })).status, 409);
    const ordinary = await f.login(operator); assert.equal((await f.request('/api/admin/users', { headers: { Cookie: ordinary.cookie } })).status, 403);
  } finally { await f.close(); }
});

test('MFA is checked and each code is consumed once across concurrent requests', async () => {
  const f = await fixture();
  try {
    const account = await user(f.store, 'admin', 'mfa-admin'), secret = newTotpSecret();
    f.store.db.prepare('UPDATE users SET totp_cipher=? WHERE id=?').run(f.store.vault.seal(secret, `totp:${account.id}`), account.id);
    const request = (otp: string) => f.request('/api/login', { method: 'POST', headers: { Origin: f.config.publicUrl, 'Content-Type': 'application/json' }, body: JSON.stringify({ username: account.username, password: 'test-only-password-42!', otp }) });
    assert.equal((await request('')).status, 401);
    const code = totp(secret); const replies = await Promise.all([request(code), request(code)]); assert.deepEqual(replies.map(r => r.status).sort(), [200, 401]);
  } finally { await f.close(); }
});
