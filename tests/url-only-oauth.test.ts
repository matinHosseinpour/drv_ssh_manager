import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { UnauthorizedError, type OAuthClientProvider, type OAuthDiscoveryState } from '@modelcontextprotocol/sdk/client/auth.js';
import type { OAuthClientInformationMixed, OAuthClientMetadata, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { fixture, user } from './helpers.js';
import { digest } from '../src/security.js';

class SavedConnection implements OAuthClientProvider {
  registration?: OAuthClientInformationMixed;
  savedTokens?: OAuthTokens;
  discovery?: OAuthDiscoveryState;
  verifier = '';
  authorizationUrl?: URL;
  redirects = 0;
  stateValue = randomUUID();
  redirectUrl = 'https://chatgpt.com/connector_platform_oauth_redirect';
  clientMetadata: OAuthClientMetadata = { client_name: 'URL-only integration test', redirect_uris: [this.redirectUrl], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] };
  clientInformation() { return this.registration; }
  saveClientInformation(value: OAuthClientInformationMixed) { this.registration = value; }
  tokens() { return this.savedTokens; }
  saveTokens(value: OAuthTokens) { this.savedTokens = value; }
  state() { return this.stateValue; }
  redirectToAuthorization(url: URL) { this.authorizationUrl = url; this.redirects++; }
  saveCodeVerifier(value: string) { this.verifier = value; }
  codeVerifier() { return this.verifier; }
  saveDiscoveryState(value: OAuthDiscoveryState) { this.discovery = value; }
  discoveryState() { return this.discovery; }
  invalidateCredentials(scope: string) {
    if (scope === 'tokens' || scope === 'all') this.savedTokens = undefined;
    if (scope === 'client' || scope === 'all') this.registration = undefined;
    if (scope === 'discovery' || scope === 'all') this.discovery = undefined;
  }
}

test('one MCP URL discovers OAuth, registers a public client and refreshes without another browser login', async () => {
  const f = await fixture();
  const provider = new SavedConnection();
  const endpoint = new URL(`${f.config.publicUrl}/mcp`);
  let client: Client | undefined;
  try {
    const account = await user(f.store, 'admin', 'url-only-admin');
    let transport = new StreamableHTTPClientTransport(endpoint, { authProvider: provider });
    client = new Client({ name: 'url-only-test', version: '1.0.0' });
    await assert.rejects(client.connect(transport), UnauthorizedError);
    assert(provider.registration?.client_id);
    assert(!('client_secret' in provider.registration));
    assert.equal(provider.redirects, 1);
    assert(provider.authorizationUrl);
    const session = await f.login(account);
    const consent = await f.request(provider.authorizationUrl.pathname + provider.authorizationUrl.search, { headers: { Cookie: session.cookie } });
    assert.equal(consent.status, 200);
    const request = (await consent.text()).match(/name="request" value="([^"]+)"/)![1]!;
    const allowed = await f.request('/oauth/consent', { method: 'POST', headers: { Cookie: session.cookie, Origin: f.config.publicUrl, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ request, csrf: session.csrf, decision: 'allow' }) });
    assert.equal(allowed.status, 303);
    const callback = new URL(allowed.headers.get('location')!);
    assert.equal(callback.searchParams.get('state'), provider.stateValue);
    await transport.finishAuth(callback.searchParams.get('code')!);
    await client.close();
    transport = new StreamableHTTPClientTransport(endpoint, { authProvider: provider });
    client = new Client({ name: 'url-only-test', version: '1.0.0' });
    await client.connect(transport);
    assert(provider.savedTokens!.scope?.includes('gateway:manage'));
    const tools = await client.listTools();
    assert.equal(tools.tools.length, 18);
    assert(tools.tools.some(tool => tool.name === 'set_server_grant'));
    const profile = await client.callTool({ name: 'get_profile', arguments: {} });
    assert(JSON.stringify(profile).includes(account.id));
    const oldAccess = provider.savedTokens!.access_token, oldRefresh = provider.savedTokens!.refresh_token!;
    const idleExpiry = f.store.db.prepare('SELECT expires_at FROM tokens WHERE hash=?').get(digest(oldRefresh)) as { expires_at: number };
    assert(idleExpiry.expires_at > Date.now() + 89 * 86400000);
    // Persisted OAuth credentials survive loss of the browser session and a new transport.
    f.store.db.prepare('DELETE FROM sessions WHERE user_id=?').run(account.id);
    f.store.db.prepare('UPDATE tokens SET expires_at=? WHERE hash=?').run(Date.now() - 1, digest(oldAccess));
    await client.close();
    transport = new StreamableHTTPClientTransport(endpoint, { authProvider: provider });
    client = new Client({ name: 'reconnected-client', version: '1.0.0' });
    await client.connect(transport);
    await client.callTool({ name: 'list_servers', arguments: {} });
    assert.notEqual(provider.savedTokens!.access_token, oldAccess);
    assert.notEqual(provider.savedTokens!.refresh_token, oldRefresh);
    assert.equal(provider.redirects, 1);
    assert.equal((f.store.db.prepare('SELECT count(*) AS n FROM clients').get() as { n: number }).n, 1);
    assert.equal((f.store.db.prepare("SELECT count(*) AS n FROM audit WHERE action='oauth.consent'").get() as { n: number }).n, 1);
  } finally { await client?.close(); await f.close(); }
});

test('a limited account cannot obtain management scope by requesting every advertised scope', async () => {
  const f = await fixture(); const provider = new SavedConnection();
  const endpoint = new URL(`${f.config.publicUrl}/mcp`);
  let client: Client | undefined;
  try {
    const account = await user(f.store, 'operator', 'limited-scope-user');
    const transport = new StreamableHTTPClientTransport(endpoint, { authProvider: provider });
    client = new Client({ name: 'limited-test', version: '1.0.0' });
    await assert.rejects(client.connect(transport), UnauthorizedError);
    assert(provider.authorizationUrl!.searchParams.get('scope')!.includes('gateway:manage'));
    const session = await f.login(account);
    const consent = await f.request(provider.authorizationUrl!.pathname + provider.authorizationUrl!.search, { headers: { Cookie: session.cookie } });
    const html = await consent.text(); assert(!html.includes('اختیار مدیریتی:'));
    const request = html.match(/name="request" value="([^"]+)"/)![1]!;
    const allowed = await f.request('/oauth/consent', { method: 'POST', headers: { Cookie: session.cookie, Origin: f.config.publicUrl, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ request, csrf: session.csrf, decision: 'allow' }) });
    await transport.finishAuth(new URL(allowed.headers.get('location')!).searchParams.get('code')!);
    await client.close(); client = new Client({ name: 'limited-test', version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(endpoint, { authProvider: provider }));
    assert.equal(provider.savedTokens!.scope, 'servers:access');
    const tools = await client.listTools(); assert(!tools.tools.some(tool => tool.name === 'update_user_access'));
    assert((await client.callTool({ name: 'list_users', arguments: {} })).isError);
  } finally { await client?.close(); await f.close(); }
});
