# Validation record

Prepared on 2026-11-22 (Asia/Tehran).

## Verified locally

- `npm run check`: TypeScript checking and 26 tests passed on Node.js 20.19.2.
- `npm run build`: production JavaScript emitted successfully.
- `npm run test:cli`: a real PTY confirmed hidden password entry and MFA enrollment, persistent account creation, an encrypted MFA seed, online backup, overwrite prevention and audit verification. A prompt/terminal-echo race found by this test was corrected and the regression passed.
- `npm audit --omit=dev --audit-level=high`: zero known vulnerabilities reported at the time of the check.
- `docker compose config --quiet`: production configuration parsed successfully with placeholder domain/network values; no real credentials were used.
- `npm run test:installer`: 13 additional tests passed, covering validation/injection rejection, dotenv safety, rerun/key preservation, missing-key refusal, symlinks, existing data, network/port conflicts, Docker version checks, Nginx templates and preservation of other sites.
- ShellCheck passed for `script.sh`. The Nginx Compose override was parsed and checked for loopback-only publication, the exact trusted bridge, coherent custom subnet addresses and exclusion of the Caddy profile.
- Both rendered Nginx templates passed real `nginx -t` using an isolated, locally compiled Nginx 1.30.7 from the official source. Temporary self-signed test key material and isolated log/certificate paths were used; no listener was started and no host Nginx configuration was changed. This is syntax proof on macOS, not proof of host installation on Linux.
- Safari: logged into an ephemeral, in-memory QA instance with a test-only administrator; visually inspected the Persian dashboard, empty server/job counts, server creation dialog and empty grants screen. No production account or target was created. The temporary server is stopped after inspection.

## Automated coverage

The tests cover authenticated encryption/context separation, password verification, a TOTP reference vector and replay/concurrency protection, CIDR restrictions, production configuration, audit tampering and output redaction.

HTTP integration covers sessions, CSRF, Host/Origin checks, administrative authorization, exact OAuth callbacks, browser consent, PKCE, resource mismatch, single-use codes, refresh rotation/reuse, account disable, credential non-disclosure, target revisions and protection of the last administrator.

An official MCP SDK client performs initialization, lists the role-appropriate tools (10 base / 18 with management consent), reads permitted servers and submits a pending command over Streamable HTTP using an issued OAuth access token. Approval tools are absent from MCP. A URL-only official SDK test discovers metadata, dynamically registers a client without manual credentials, completes one browser consent, deletes browser sessions, expires the access token and reconnects by rotating the refresh token with no second browser redirect. A limited-account test verifies that requesting every advertised scope does not grant management authority.

Management integration tests verify scope and role boundaries, shared web/service authorization, private-key non-disclosure, server enrollment, revision conflicts, grants, final-administrator protection and live account revocation.

Job tests cover human approval, command-digest checks, idempotent request keys, role/server scope, changing targets, revoked grants, abort of running work and the single-worker lease.

SSH tests use a real local `ssh2.Server` endpoint with an ephemeral RSA host key. They perform the SSH handshake, password authentication and authentication with an encrypted Ed25519 private key, verify host fingerprint rejection before authentication, check command quoting/wrapping, receive stdout/stderr, exercise output limits and cancel a live channel. The test endpoint does not execute a Linux shell; it verifies the SSH protocol and gateway behavior.

## Not verified in this environment

- Docker image build/start: the Docker daemon was unavailable. Compose parsing is not image or runtime proof.
- Full root installer on Ubuntu/Debian, package installation, service management, real Let's Encrypt issuance/renewal and recovery of a live prior Caddy deployment have not been executed in this environment. The installer has regression/static/configuration checks; the Linux CI job is defined but has not run remotely here.
- A real Linux destination: no target address, credentials or independently verified host key were supplied. GNU timeout behavior and actual target permissions must be checked there.
- Public HTTPS, DNS, firewall/VPN routing or certificate issuance: the requested domain is server.darvishipioneers.com; the user confirmed that installation has not run. No server deployment or real certificate issuance is claimed.
- An authenticated connection installed in GPT Work/ChatGPT: local SDK OAuth/MCP success is not proof of a live product connection.
- CI matrix on Linux/Node.js 22: workflow is included, but it has not been run by a remote CI service.

Use a dedicated operator account for acceptance: grant exactly one server, call list_servers, run the system diagnostic and inspect its output, request a harmless command and verify it stays pending, approve it in the browser, inspect its final output, then revoke the connection and confirm a 401. Test each additional server independently before enabling operational use.
