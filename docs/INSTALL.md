# Automatic Linux host installation

Extract the complete source archive on an Ubuntu 22.04/24.04 or Debian 12/13 systemd host. Run this from its source directory:

```sh
sudo bash script.sh
```

Node.js is not required on the host. The installer installs base utilities, Docker Engine/Compose when absent, host Nginx and Certbot. Application dependencies and builds run inside the Node.js 22 image. No default password is created. After successful installation, enter https://server.darvishipioneers.com/mcp in Custom MCP and complete the browser OAuth sign-in; manual client credentials are not required. See MCP_CONNECTION.md.

The default hostname is server.darvishipioneers.com and the standard issuer-bound GPT OAuth callback is preconfigured. Existing explicit settings take precedence. On a first installation it asks for the certificate contact email, allowed SSH destination CIDRs, acceptance of the certificate subscriber terms and the initial administrator username. Password entry and MFA enrollment use the existing private terminal prompts. Account creation occurs before the panel is publicly proxied.

## Requirements outside the installer's control

- A domain whose DNS reaches this host. Configure both A and AAAA correctly if both exist. HTTP-01 validation needs public TCP port 80; normal access needs TCP 443. Cloud-provider firewall rules and DNS-provider records require those providers' credentials and are not changed by this script.
- Outbound access to OS repositories, `download.docker.com`, Docker image registries, npm during the container build, Let's Encrypt and the Linux target network.
- A rootful local Docker daemon. Docker Engine 28.3.3 or newer is required for the chosen loopback port isolation. The installer does not remove or silently upgrade a conflicting existing Docker/containerd/Kubernetes installation. This version floor covers the loopback isolation issue described in [Docker's 28.3.3 security notes](https://docs.docker.com/engine/release-notes/28/#2833).
- An interactive SSH terminal and access to an authenticator application for the initial MFA administrator.

## What the installer owns

| Resource | Purpose |
|---|---|
| Project `.env` | Domain, SSH allowlist, exact OAuth callbacks, chosen port and Docker network |
| Project `secrets/master_key` | Original 256-bit encryption/signing key; preserved on every rerun |
| Project `.installer/backups/` | Private snapshots of prior environment and managed Nginx site |
| Docker project `server-connector` | Gateway container and existing persistent data volume |
| `/etc/nginx/sites-available/server-connector.conf` | Managed HTTP/HTTPS configuration |
| `/etc/nginx/sites-enabled/server-connector.conf` | Symlink to the managed configuration |
| `/var/lib/server-connector/acme/` | HTTP-01 challenge webroot |
| `/etc/letsencrypt/live/server-connector-DOMAIN/` | Certificate lineage created by Certbot |
| `/etc/letsencrypt/renewal-hooks/deploy/server-connector-nginx.sh` | Validates and reloads Nginx after renewal |
| `certbot.timer` | OS-provided scheduled renewal |

The gateway is published as `127.0.0.1:PORT -> container:3080`. Nginx forwards the public Host unchanged, overwrites untrusted forwarding headers and preserves every original request path. Only the Docker bridge gateway is trusted to supply forwarded client IPs. Access logs are disabled for the managed site and its error log is restricted to critical errors.

The initial HTTP site serves only the ACME challenge and a setup-in-progress response. It does not expose the login form over plaintext HTTP. The final HTTP site redirects to HTTPS while retaining the challenge route. TLS uses versions 1.2 and 1.3. IPv6 listen directives are omitted if IPv6 is disabled on the host.

The installer adds TCP 80/443 to UFW or firewalld only when that firewall is already active. It does not enable/reset a firewall or modify SSH firewall rules. Docker uses its normal host networking rules; no Docker daemon-wide network policy is rewritten.

## Reruns, existing installations and failure behavior

Rerun the same command to rebuild and validate an existing installation. Saved settings are reused; an active MFA administrator is preserved. The application may restart during this operation, so avoid running upgrades during important remote jobs. Running SSH work is not blindly retried.

The script never runs `docker compose down -v`, deletes a data volume or replaces an existing master key. If a data volume exists and the original key is missing, it refuses to generate a replacement. A valid older `MASTER_KEY` stored in the project environment can be imported into the private key file; the plaintext environment copy is removed from the active file after import. Keep the original key backed up separately from the database and protect the installer's private environment backups too.

Existing project network addresses are preserved. For a fresh installation the script chooses a private /29 without overlap with IPv4 routes, other Docker networks or the declared SSH destination networks. It chooses a free loopback port between 3080 and 3099 unless one was already configured. An occupied configured port is never taken from another service.

Other Nginx site files remain untouched. An exact domain or filename conflict causes a stop rather than replacing an unrelated site. A running Caddy container belonging to this exact Docker project can be migrated to host Nginx; its volumes are preserved. Other Caddy/Apache containers or web servers are not stopped. The `caddy` Compose profile is optional and excluded from the Nginx installation.

Before changing the managed Nginx site the installer saves the prior file and enabled-site link. On failure before deployment is committed it restores that site. If it stopped this project's old Caddy, it restores the prior environment/gateway configuration and attempts to restart that Caddy. OS packages, firewall openings and issued certificates are not uninstalled on failure; package installation is not a host-wide transaction. A fresh failed installation can retain a private gateway and its original data for a safe rerun.

Nginx is tested before every start/reload. The script checks the local HTTP challenge, the real HTTPS listener and OAuth metadata, runs a Certbot renewal dry run, and checks access through public DNS before reporting completion. A DNS/NAT problem can prevent a host reaching its own public name; in that final failure case, the verified local deployment remains installed and the script reports the incomplete public check.

The installer does not configure the Linux destination accounts, copy arbitrary SSH credentials or accept an unverified host key. Add those through the panel using the target preparation steps in the main README.

## Service operations

For this Nginx deployment use both Compose files, from the project directory:

```sh
sudo docker compose -f compose.yaml -f deploy/compose.nginx.yaml ps
sudo docker compose -f compose.yaml -f deploy/compose.nginx.yaml logs --tail=100 gateway
sudo nginx -t
sudo systemctl status nginx certbot.timer
```

Do not print `.env`, the master key, authorization headers or unsanitized credential-bearing logs into a support conversation. The application intentionally logs only sanitized error types and audit metadata.

## Verification and upstream references

```sh
npm run test:installer
shellcheck script.sh
# Optional: requires an nginx executable and openssl; never starts a server.
npm run test:nginx
```

The installer follows the signed Docker repository instructions for [Ubuntu](https://docs.docker.com/engine/install/ubuntu/) and [Debian](https://docs.docker.com/engine/install/debian/), [Nginx proxy header/path behavior](https://nginx.org/en/docs/http/ngx_http_proxy_module.html), and Certbot's [webroot and renewal workflow](https://eff-certbot.readthedocs.io/en/stable/using.html). Local regression and syntax checks are distinct from a real installation with public DNS, certificate issuance and an authenticated GPT connection; see `VALIDATION.md`.
