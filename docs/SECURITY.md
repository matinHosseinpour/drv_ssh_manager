# Security model

This is a self-hosted, single-instance SSH execution gateway. Its trust boundary is the gateway host, master key, SQLite database, administrators and Linux account permissions. It does not make an unrestricted shell safe by inspecting command text.

## Authorization and human approval

Web sessions and OAuth tokens resolve to the same active user record. Account changes increase an authorization version, invalidating old sessions and tokens. Server grants are evaluated on every operation and again before execution. Viewer accounts cannot request arbitrary commands even if their execute grant is set.

Administrators can manage all targets. Operators and viewers only discover granted targets. MCP server listings omit IP addresses, usernames, fingerprints and credential metadata for every role. The administrative browser interface can see connection metadata; no API returns stored SSH credentials.

Every arbitrary command starts pending. Only a browser session belonging to a current administrator can approve it, with a valid same-origin CSRF token and matching SHA256 command digest. OAuth bearer tokens cannot approve jobs. The target revision, requester authorization version and approving administrator version are checked before execution. Changes to target settings invalidate outstanding jobs. Grants and account status are rechecked during execution at 500 ms intervals; aborting a running channel is best effort.

A diagnostic is one of five hardcoded commands without interpolated arguments. These are not a guarantee against a compromised target replacing its system utilities. Treat returned data as untrusted. Execution tools only reference registered server IDs. An administrator with explicit management consent may register a literal, allowlisted IP target with a verified fingerprint; credential handling and authorization still run on the server.

## Credential storage and authentication

- Credentials, MFA seeds, commands, reasons and job results use AES-256-GCM with random 96-bit nonces and record-specific authenticated context. Ciphertext cannot be moved between records without authentication failure.
- The 256-bit master key comes from an environment variable or a mounted file. Production Compose mounts a generated file. Never commit it, send it to GPT, expose it in a URL or include it in backups alongside the database. The application process necessarily holds decrypted credentials while establishing SSH.
- Passwords use scrypt with independent random salts (N=32768, r=8, p=1). Minimum length is 14 characters. No default user is created.
- TOTP is required in production. A consumed time step cannot be reused, including concurrent login attempts. The host needs synchronized time. MFA enrollment keys are deliberately shown once to the account creator; handle them as credentials. Recovery is a local operator procedure.
- Browser cookies are HttpOnly, SameSite=Lax, Secure in production and host-only with the `__Host-` prefix. Sessions expire after eight hours. Login checks exact Origin, JSON content type, per-IP limits and per-username lockout.
- Only expressly configured reverse proxies may supply forwarded client IPs. The app verifies the public Host and rejects foreign or null Origin. Same-origin web mutations require a session and CSRF token. The reverse proxy must preserve Host and avoid logging query strings or auth headers.

## OAuth / MCP

The gateway publishes protected-resource metadata and OAuth authorization-server metadata. It implements public-client DCR, exact callback allowlisting, PKCE S256, 60-second single-use authorization codes, audience/resource binding and two scopes: `servers:access` for scoped server work, and `gateway:manage` for administrative management. The second scope is granted only to an administrator, described explicitly on the consent screen, and rechecked at every call. Old server-only tokens do not gain management authority automatically. Neither scope overrides server grants for limited users.

Registration is unauthenticated by design, IP rate limited, callback restricted and capped at 1,000 clients. DCR is client registration, not user authorization. Client names are untrusted and escaped on consent screens. Client Metadata Document URLs are not fetched or accepted as client IDs. Unsupported OAuth clients need an adapter rather than a bypass.

Access tokens expire after ten minutes. Refresh tokens have a 90-day inactivity lifetime by default (`OAUTH_REFRESH_IDLE_DAYS`, configurable up to 365), rotate on use and revoke earlier access tokens. Every successful refresh gets a new inactivity expiry. The MCP client retains and rotates these tokens independently of the eight-hour browser session; everyday use does not require repeated sign-in. Reuse of a consumed refresh token revokes its family. Token and code database entries contain hashes, not raw values. Disabling an account or changing its password, role or MFA invalidates all previous token versions. Revoking a connection stops subsequent API use; submitted jobs are separate durable operations and must be cancelled explicitly if desired.

Administrative tools share the management service and final-administrator/revision checks with web routes. They may register a new Ed25519 key locally and return only its public key; the private key remains encrypted in the gateway. Password creation, MFA enrollment and private credential changes use the browser panel. An administrative bearer token still cannot approve arbitrary shell commands. Each MCP request receives a new SDK server and stateless Streamable HTTP transport. GET/SSE sessions and terminal streaming are not exposed. Every tool includes OAuth metadata; command tools are marked destructive. These annotations guide clients and are not security enforcement. The server enforces all permissions itself.

## SSH and remote process boundaries

Only literal IP targets inside the configured CIDRs are accepted, preventing DNS rebinding. Default routes, IPv4-mapped IPv6, zone IDs, unspecified, multicast and link-local addresses are rejected. Loopback is possible only when expressly allowlisted. A host's SHA256 key fingerprint must be supplied from an independent trusted console; there is no trust-on-first-use mode.

The SSH client uses the selected password or private key only, disables interactive authentication and agent forwarding and does not request a PTY. Each job creates a new SSH connection. Root username is rejected, but this does **not** prevent root-equivalent privileges through sudo, Docker, filesystem permissions or a root-equivalent account. Configure least privilege on each Linux target and firewall SSH to the gateway's actual source IP.

Commands are quoted once as a single `/bin/sh -c` argument and wrapped with GNU `timeout` on the target. Connection setup is limited to ten seconds. A local watchdog bounds connection plus execution, and output is bounded. Process groups normally terminate with timeout; intentionally daemonized or detached processes can survive a cancelled connection. `remoteState: unknown` and `interrupted` must trigger human inspection, not blind retries. The application never automatically retries an SSH command.

Stored/output redaction removes known connection credentials and common token/password/private-key patterns. It is a best-effort filter, **not** a data-loss-prevention guarantee. A command can print any secret the Linux account can read, encode it or split it across outputs. Approve commands accordingly, restrict remote file access and treat output sent to GPT as disclosure to that product/account. Do not paste secrets into commands; use a reviewed remote script with server-side secret injection when needed.

## Persistence and audit limitations

SQLite uses foreign keys, WAL and FULL synchronization. A process lease rejects a second live worker. The deployment supports one process/replica and a local disk. Per-server concurrency is one; global concurrency and pending queues are bounded. Worker restarts mark in-progress jobs interrupted rather than rerunning them. A lease can expire during a stalled process, so distributed exactly-once execution is not claimed.

Audit records contain actor IDs, actions, resource IDs, command digests and result metadata. They exclude command text, reasons, output and credentials. HMAC links detect modifications and gaps in the retained chain. Copy a checkpoint to independent storage to detect truncation of the tail. An attacker who controls the host, database and signing key can alter or replace the system. The database and administrators are trusted: the audit chain is not an independent authorization engine or WORM storage.

Retention removes completed job rows logically. It does not securely erase historical ciphertext from snapshots, database free pages or backups. Audit rows remain and must be monitored for disk growth. Protect backup destinations and export independent checkpoints. Rotating a compromised master key requires an offline migration or recreation of encrypted records and a new audit chain with a recorded old checkpoint; changing the configured key alone is not a rotation procedure.

## Deployment boundaries

The automatic installer uses host Nginx for public HTTP/HTTPS and publishes the non-root gateway only on an explicit loopback address. The gateway has a read-only root filesystem, dropped capabilities, no-new-privileges and process/memory limits; its image has no Docker socket or host filesystem mount. Only the exact Docker bridge address is trusted for forwarded client IPs. The old Caddy topology remains an optional Compose profile. The application requires outbound access to the configured SSH network; enforce an egress firewall outside the application as a second boundary. Update and pin container image digests under your deployment policy.

The installer operates as root, installs packages from signed OS/Docker repositories and configures Nginx, Certbot and an already active firewall. It never executes dotenv contents as shell code, never deletes data volumes, and refuses a missing original key for an existing data volume. It preserves unrelated sites and does not resolve conflicts by stopping unrelated services or deleting conflicting packages. Its Nginx rollback is limited to its own site and an attempted recovery of this project's prior Caddy topology, not an undo of every host package/firewall/certificate change. Certificate subscriber terms are accepted interactively before issuance. The initial administrator's password is never passed on a command line, written into environment settings or emitted by the installer.

This repository includes automated security regression tests and transport integration tests. It has not received an independent penetration test or an authenticated live GPT connection test against the user's real infrastructure. TLS issuance, routing, host identity, remote privilege boundaries, backups and deployment monitoring require environment-specific verification.
