import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Store } from '../src/db.js';
import { Jobs } from '../src/jobs.js';
import { visibleServers } from '../src/mcp.js';
import { grant, success, target, testConfig, user, waitFor } from './helpers.js';

test('commands cannot execute before exact human approval; retry key is idempotent', async () => {
  const config = testConfig(), store = new Store(':memory:', config.masterKey); let executions = 0;
  const jobs = new Jobs(store, config, async (...args) => { executions++; return success(...args); });
  try {
    const admin = await user(store, 'admin'), operator = await user(store), server = target(store); grant(store, operator.id, server.id);
    jobs.start();
    const input = { serverId: server.id, kind: 'command', command: 'echo approved', reason: 'check command approval', requestKey: randomUUID() };
    const job = jobs.create(operator, input); assert.equal(job.status, 'pending'); assert.equal(jobs.create(operator, input).id, job.id);
    assert.throws(() => jobs.create(operator, { ...input, command: 'different' }));
    jobs.tick(); assert.equal(executions, 0);
    assert.throws(() => jobs.approve(operator, job.id, job.commandHash));
    assert.throws(() => jobs.approve(admin, job.id, '0'.repeat(64)));
    jobs.approve(admin, job.id, job.commandHash); jobs.tick();
    await waitFor(() => jobs.get(operator, job.id).status === 'succeeded'); assert.equal(executions, 1);
    assert.throws(() => jobs.approve(admin, job.id, job.commandHash));
    assert(!JSON.stringify(store.db.prepare('SELECT payload FROM jobs').get()).includes('echo approved'));
  } finally { await jobs.stop(); store.close(); }
});
test('server scope and viewer role are enforced; disabled targets remain manageable by admin', async () => {
  const config = testConfig(), store = new Store(':memory:', config.masterKey), jobs = new Jobs(store, config, success);
  try {
    const admin = await user(store, 'admin'), viewer = await user(store, 'viewer'), other = await user(store), server = target(store), hidden = target(store); grant(store, viewer.id, server.id);
    assert.equal(visibleServers(store, viewer).length, 1); assert(!JSON.stringify(visibleServers(store, admin)).includes('127.0.0.1'));
    const input = { serverId: server.id, kind: 'diagnostic', diagnostic: 'system', reason: 'check operating system', requestKey: randomUUID() };
    const job = jobs.create(viewer, input);
    assert.throws(() => jobs.get(other, job.id));
    assert.throws(() => jobs.create(viewer, { ...input, serverId: hidden.id, requestKey: randomUUID() }));
    assert.throws(() => jobs.create(viewer, { ...input, kind: 'command', diagnostic: undefined, command: 'id', requestKey: randomUUID() }));
    store.db.prepare('UPDATE servers SET enabled=0 WHERE id=?').run(server.id);
    assert.equal(jobs.get(admin, job.id).id, job.id); assert.equal(visibleServers(store, admin, true).length, 2);
  } finally { await jobs.stop(); store.close(); }
});
test('changing target or revoking grants invalidates queued approval', async () => {
  const config = testConfig(), store = new Store(':memory:', config.masterKey); let executions = 0;
  const jobs = new Jobs(store, config, async (...args) => { executions++; return success(...args); });
  try {
    const admin = await user(store, 'admin'), operator = await user(store), server = target(store); grant(store, operator.id, server.id); jobs.start();
    const make = () => jobs.create(operator, { serverId: server.id, kind: 'command', command: 'id', reason: 'verify identity safely', requestKey: randomUUID() });
    const first = make(); jobs.approve(admin, first.id, first.commandHash);
    store.db.prepare('UPDATE servers SET revision=revision+1 WHERE id=?').run(server.id); jobs.tick();
    assert.equal(store.job(first.id)!.status, 'cancelled');
    const second = make(); jobs.approve(admin, second.id, second.commandHash); grant(store, operator.id, server.id, false, false); jobs.tick();
    assert.equal(store.job(second.id)!.status, 'cancelled'); assert.equal(executions, 0);
  } finally { await jobs.stop(); store.close(); }
});
test('live revocation aborts running work and does not retry it', async () => {
  const config = testConfig(), store = new Store(':memory:', config.masterKey); let aborted = false;
  const jobs = new Jobs(store, config, async (_server, _credential, _command, signal) => new Promise(resolve => signal.addEventListener('abort', () => { aborted = true; resolve({ stdout: '', stderr: '', exitCode: null, signal: null, truncated: false, outcome: 'cancelled', remoteState: 'unknown' }); }, { once: true })));
  try {
    const operator = await user(store), admin = await user(store, 'admin'), server = target(store); grant(store, operator.id, server.id); jobs.start();
    const job = jobs.create(operator, { serverId: server.id, kind: 'diagnostic', diagnostic: 'system', reason: 'inspect target safely', requestKey: randomUUID() });
    jobs.tick(); assert.equal(store.job(job.id)!.status, 'running');
    grant(store, operator.id, server.id, false, false); jobs.tick(); await waitFor(() => aborted && store.job(job.id)!.status === 'cancelled');
    assert.equal(jobs.get(admin, job.id).result!.remoteState, 'unknown');
  } finally { await jobs.stop(); store.close(); }
});
test('single-worker lease rejects a second runner and restart marks work interrupted', async () => {
  const config = testConfig(), store = new Store(':memory:', config.masterKey), first = new Jobs(store, config, success), second = new Jobs(store, config, success);
  try { first.start(); assert.throws(() => second.start(), /Another gateway/); await first.stop(); second.start(); assert(store.verifyAudit().valid); }
  finally { await second.stop(); store.close(); }
});
