import ssh2, { type ClientChannel } from 'ssh2';
import { createHash } from 'node:crypto';
import type { Config } from './config.js';
import { checkTarget } from './config.js';
import type { Server } from './db.js';
import { equal, redact } from './security.js';

export type Credential = { type: 'password'; password: string } | { type: 'key'; privateKey: string; passphrase?: string };
export type ExecutionResult = {
  stdout: string; stderr: string; exitCode: number | null; signal: string | null;
  truncated: boolean; outcome: 'completed' | 'timeout' | 'cancelled' | 'connection_error' | 'output_limit'; remoteState: 'finished' | 'unknown';
};
export type Executor = (server: Server, credential: Credential, command: string, signal: AbortSignal) => Promise<ExecutionResult>;
export const shellQuote = (value: string) => `'${value.replace(/'/g, `'"'"'`)}'`;

export function sshExecutor(config: Config): Executor {
  return (server, credential, command, signal) => new Promise((resolve) => {
    checkTarget(config, server.address);
    const client = new ssh2.Client(); let channel: ClientChannel | undefined;
    let done = false, verified = false, bytes = 0, stdout = '', stderr = '', truncated = false;
    const secrets = credential.type === 'password' ? [credential.password] : [credential.privateKey, credential.passphrase || ''];
    const finish = (outcome: ExecutionResult['outcome'], exitCode: number | null = null, exitSignal: string | null = null, remoteState: ExecutionResult['remoteState'] = 'unknown') => {
      if (done) return; done = true;
      clearTimeout(timer); signal.removeEventListener('abort', abort);
      if (outcome !== 'completed') { try { channel?.signal('TERM'); } catch {} }
      channel?.close(); client.destroy();
      resolve({ stdout: redact(stdout, secrets), stderr: redact(stderr, secrets), exitCode, signal: exitSignal, truncated, outcome, remoteState });
    };
    const timer = setTimeout(() => finish('timeout'), (config.timeout + 20) * 1000);
    const abort = () => finish('cancelled');
    if (signal.aborted) { finish('cancelled'); return; }
    signal.addEventListener('abort', abort, { once: true });
    const consume = (chunk: Buffer | string, stream: 'stdout' | 'stderr') => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const kept = buffer.subarray(0, Math.max(0, config.outputLimit - bytes)); bytes += kept.length;
      if (stream === 'stdout') stdout += kept.toString('utf8'); else stderr += kept.toString('utf8');
      if (kept.length < buffer.length) { truncated = true; finish('output_limit'); }
    };
    client.on('ready', () => {
      // GNU timeout on the target bounds descendants even if the gateway disconnects.
      const wrapped = `exec timeout --signal=TERM --kill-after=5s ${config.timeout}s /bin/sh -c ${shellQuote(command)}`;
      client.exec(wrapped, { pty: false }, (err, stream) => {
        if (done) { stream?.close(); return; }
        if (err) { stderr = 'SSH command channel could not be opened'; finish('connection_error'); return; }
        channel = stream;
        stream.on('data', (data: Buffer) => consume(data, 'stdout'));
        stream.stderr.on('data', (data: Buffer) => consume(data, 'stderr'));
        stream.on('error', () => finish('connection_error'));
        stream.on('close', (code: number | undefined, sig: string | undefined) => {
          const known = typeof code === 'number' || !!sig;
          finish(code === 124 || code === 137 ? 'timeout' : known ? 'completed' : 'connection_error', code ?? null, sig || null, known ? 'finished' : 'unknown');
        });
      });
    });
    client.on('error', () => { if (!stderr) stderr = verified ? 'SSH connection or authentication failed' : 'SSH connection failed or host fingerprint did not match'; finish('connection_error'); });
    client.on('close', () => finish('connection_error'));
    try { client.connect({
      host: server.address, port: server.port, username: server.username,
      ...(credential.type === 'password' ? { password: credential.password } : { privateKey: credential.privateKey, passphrase: credential.passphrase }),
      hostVerifier: (key: Buffer) => {
        const fingerprint = `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`;
        verified = equal(fingerprint, server.fingerprint); return verified;
      },
      readyTimeout: 10000, keepaliveInterval: 5000, keepaliveCountMax: 2,
      tryKeyboard: false, agentForward: false,
      authHandler: credential.type === 'password' ? ['password'] : ['publickey'],
    }); } catch { stderr = 'SSH configuration could not be loaded'; finish('connection_error'); }
  });
}
