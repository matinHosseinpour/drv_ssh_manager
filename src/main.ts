import { loadConfig } from './config.js';
import { Store } from './db.js';
import { Jobs } from './jobs.js';
import { sshExecutor } from './ssh.js';
import { createApp } from './app.js';

const config = loadConfig();
const store = new Store(config.databasePath, config.masterKey);
if (!store.verifyAudit().valid) throw new Error('Audit integrity check failed; investigate before starting');
const jobs = new Jobs(store, config, sshExecutor(config));
jobs.start(); jobs.maintenance();
const app = await createApp(store, config, jobs);
const server = app.listen(config.port, config.host, () => console.log(JSON.stringify({ event: 'gateway_started', port: config.port })));
const maintenance = setInterval(() => jobs.maintenance(), 3600000); maintenance.unref();
let stopping = false;
async function shutdown() {
  if (stopping) return; stopping = true;
  clearInterval(maintenance);
  const closed = new Promise<void>(resolve => { server.close(() => resolve()); server.closeIdleConnections(); });
  await jobs.stop(); await closed; store.close();
}
process.on('SIGINT', () => void shutdown()); process.on('SIGTERM', () => void shutdown());
server.on('error', async () => { console.error('Gateway listen failed'); await jobs.stop(); store.close(); process.exitCode = 1; });
