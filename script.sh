#!/usr/bin/env bash
# Interactive host installer for Ubuntu 22.04/24.04 and Debian 12/13 with systemd.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  cat <<'HELP'
Usage: sudo bash script.sh
Run from the extracted source tree on an Ubuntu 22.04/24.04 or Debian 12/13 host.
Installs Docker Engine/Compose, Nginx and Certbot; uses server.darvishipioneers.com
unless already configured, and asks for the certificate email and SSH CIDRs;
creates private configuration and a confirmed MFA administrator; configures TLS,
renewal and a loopback-only gateway. Existing keys, volumes and other sites remain.
DNS must already point at this host; public TCP 80/443 must be reachable.
Do not pipe this script into a shell. Extract and review the source archive first.
HELP
  exit 0
fi
[[ $# == 0 ]] || { printf 'Unknown arguments. Use --help.\n' >&2; exit 1; }
[[ $(uname -s) == Linux && $EUID == 0 ]] || { printf 'Run on the Linux server with: sudo bash script.sh\n' >&2; exit 1; }

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd -- "$PROJECT_DIR"
[[ -f Dockerfile && -f compose.yaml && -f scripts/install_config.py ]] || { printf 'The complete source tree is required next to script.sh.\n' >&2; exit 1; }
[[ -r /etc/os-release ]] || { printf 'Missing /etc/os-release.\n' >&2; exit 1; }
# /etc/os-release is the trusted host OS file; project .env files are never sourced.
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
  *) printf 'Supported hosts: Ubuntu 22.04/24.04, Debian 12/13.\n' >&2; exit 1 ;;
esac
systemctl show-environment >/dev/null 2>&1 || { printf 'A running systemd host is required.\n' >&2; exit 1; }
command -v flock >/dev/null || { printf 'flock from util-linux is required by this host installer.\n' >&2; exit 1; }
exec 9>/run/lock/server-connector-install.lock
flock -n 9 || { printf 'Another Server Connector installer is running.\n' >&2; exit 1; }

# Never follow a user's remote Docker context during host installation.
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
export DOCKER_HOST=unix:///var/run/docker.sock
export DEBIAN_FRONTEND=noninteractive
STAGE=preflight
COMMITTED=0
SITE_CHANGED=0
CADDY_STOPPED=0
CADDY_ID=
SITE_EXISTED=0
LINK_EXISTED=0
ENV_EXISTED=0
BACKUP_DIR=
SITE_FILE=/etc/nginx/sites-available/server-connector.conf
SITE_LINK=/etc/nginx/sites-enabled/server-connector.conf
NGINX_WAS_ACTIVE=0
if systemctl is-active --quiet nginx; then NGINX_WAS_ACTIVE=1; fi

log() { printf '\n[Server Connector] %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
compose() { docker compose --project-name server-connector --project-directory "$PROJECT_DIR" --env-file "$PROJECT_DIR/.env" -f "$PROJECT_DIR/compose.yaml" -f "$PROJECT_DIR/deploy/compose.nginx.yaml" "$@"; }
base_compose() { docker compose --project-name server-connector --project-directory "$PROJECT_DIR" --env-file "$PROJECT_DIR/.env" -f "$PROJECT_DIR/compose.yaml" "$@"; }
config() { python3 "$PROJECT_DIR/scripts/install_config.py" --root "$PROJECT_DIR" "$@"; }

cleanup() {
  local status=$?
  trap - EXIT ERR INT TERM
  set +e
  if [[ $status != 0 ]]; then
    printf '\nInstallation did not finish during: %s\n' "$STAGE" >&2
    if [[ $COMMITTED == 0 ]]; then
      if [[ $SITE_CHANGED == 1 ]]; then
        if [[ $SITE_EXISTED == 1 ]]; then cp -a -- "$BACKUP_DIR/nginx-site" "$SITE_FILE"; else rm -f -- "$SITE_FILE"; fi
        rm -f -- "$SITE_LINK"
        if [[ $LINK_EXISTED == 1 ]]; then cp -a -- "$BACKUP_DIR/nginx-link" "$SITE_LINK"; fi
        if nginx -t; then systemctl reload nginx; fi
      fi
      if [[ $CADDY_STOPPED == 1 ]]; then
        if [[ $NGINX_WAS_ACTIVE == 0 ]]; then systemctl stop nginx; fi
        if [[ $ENV_EXISTED == 1 ]]; then
          cp -a -- "$BACKUP_DIR/env" "$PROJECT_DIR/.env"
          base_compose up -d --no-build --wait --wait-timeout 120 gateway
        fi
        docker start "$CADDY_ID" >/dev/null
      fi
    fi
    if [[ -n $BACKUP_DIR ]]; then printf 'Private configuration backup: %s\n' "$BACKUP_DIR" >&2; fi
    printf 'Keys and data volumes were retained. Fix the reported cause and rerun script.sh.\n' >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'printf "Installer command failed in stage %s (line %s).\n" "$STAGE" "$LINENO" >&2' ERR
trap 'exit 130' INT
trap 'exit 143' TERM

prompt() {
  local variable=$1 title=$2 fallback=$3 answer
  [[ -r /dev/tty && -w /dev/tty ]] || die 'Use an interactive SSH terminal for installation.'
  if [[ -n $fallback ]]; then printf '%s [%s]: ' "$title" "$fallback" >/dev/tty; else printf '%s: ' "$title" >/dev/tty; fi
  IFS= read -r answer </dev/tty || die 'Input cancelled.'
  printf -v "$variable" '%s' "${answer:-$fallback}"
  [[ -n ${!variable} ]] || die "$title is required."
}

STAGE='install base utilities'
log 'Installing base utilities from the OS package repository.'
apt-get update
apt-get install -y --no-remove --no-install-recommends ca-certificates curl gnupg python3 iproute2 openssl util-linux

STAGE='collect installation settings'
DOMAIN=$(config get GATEWAY_DOMAIN)
EMAIL=$(config get ACME_EMAIL)
SSH_CIDRS=$(config get SSH_ALLOWED_CIDRS)
CALLBACKS=$(config get OAUTH_REDIRECT_URIS)
if [[ -z $DOMAIN || $DOMAIN == *.example.com || $DOMAIN == example.com ]]; then DOMAIN=server.darvishipioneers.com; fi
if [[ -z $EMAIL || $EMAIL == *@example.com ]]; then prompt EMAIL 'Email for TLS certificate expiry notices' ''; fi
if [[ -z $SSH_CIDRS || $SSH_CIDRS == 10.20.0.10/32,10.20.0.11/32 ]]; then prompt SSH_CIDRS 'Allowed SSH target CIDRs, comma separated' ''; fi
CALLBACKS=${CALLBACKS:-https://chatgpt.com/connector_platform_oauth_redirect}
config validate --domain "$DOMAIN" --email "$EMAIL" --cidrs "$SSH_CIDRS" --callbacks "$CALLBACKS"
if [[ $(config get ACME_TERMS_ACCEPTED) != 1 ]]; then
  log "HTTPS uses Let's Encrypt. Subscriber terms: https://letsencrypt.org/repository/"
  prompt TERMS 'Accept these terms and request the certificate? Enter yes' ''
  [[ $TERMS == yes ]] || die 'Certificate terms were not accepted; no certificate requested.'
fi
timeout 20 getent ahosts "$DOMAIN" >/dev/null || die 'The public domain does not resolve yet. Point DNS at this host and rerun.'

STAGE='install Docker Engine and Compose'
docker_repository() {
  local key_file repository_file
  if grep -Rqs "https://download.docker.com/linux/$ID" /etc/apt/sources.list.d; then return; fi
  key_file=/etc/apt/keyrings/server-connector-docker.asc
  repository_file=/etc/apt/sources.list.d/server-connector-docker.sources
  [[ ! -e $repository_file ]] || die 'The dedicated Docker repository path is already occupied.'
  install -d -m 0755 /etc/apt/keyrings
  local temporary
  temporary=$(mktemp)
  if ! curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 60 "https://download.docker.com/linux/$ID/gpg" -o "$temporary"; then rm -f -- "$temporary"; die 'Cannot download the official Docker signing key.'; fi
  gpg --batch --quiet --show-keys "$temporary" >/dev/null 2>&1 || { rm -f -- "$temporary"; die 'Invalid Docker signing key response.'; }
  install -m 0644 "$temporary" "$key_file"
  rm -f -- "$temporary"
  [[ ${VERSION_CODENAME:-} =~ ^[a-z]+$ ]] || die 'Invalid OS repository codename.'
  cat >"$repository_file" <<EOF
# Managed by Server Connector installer.
Types: deb
URIs: https://download.docker.com/linux/$ID
Suites: $VERSION_CODENAME
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: $key_file
EOF
  chmod 0644 "$repository_file"
  apt-get update
}
if ! command -v docker >/dev/null || ! command -v dockerd >/dev/null; then
  docker_repository
  # Do not remove distro Docker/containerd or Kubernetes packages to resolve conflicts.
  apt-get install -y --no-remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
elif ! docker compose version >/dev/null 2>&1 || ! docker buildx version >/dev/null 2>&1; then
  docker_repository
  apt-get install -y --no-remove docker-compose-plugin docker-buildx-plugin
fi
systemctl enable --now docker
docker info >/dev/null
config check-docker "$(docker version --format '{{.Server.Version}}')"
docker compose version >/dev/null
docker compose up --help | grep -F -- --wait >/dev/null || die 'Docker Compose is too old; a version supporting up --wait is required.'

STAGE='check existing web services'
CADDY_ID=$(docker ps -q --filter label=com.docker.compose.project=server-connector --filter label=com.docker.compose.service=caddy)
[[ $CADDY_ID != *$'\n'* ]] || die 'Multiple project Caddy containers found.'
check_ports() {
  local port lines container ports line
  while IFS=$'\t' read -r container ports; do
    if [[ $ports =~ :(80|443)-\> && $container != "$CADDY_ID" ]]; then die 'Another Docker workload owns public port 80 or 443; it has not been stopped.'; fi
  done < <(docker ps --format '{{.ID}}\t{{.Ports}}')
  for port in 80 443; do
    lines=$(ss -H -ltnp "sport = :$port")
    while IFS= read -r line; do
      [[ -z $line || $line == *'"nginx"'* ]] && continue
      if [[ -n $CADDY_ID && $CADDY_STOPPED == 0 && $line == *'"docker-proxy"'* ]]; then continue; fi
      die "Port $port is owned by another web service; it has not been stopped."
    done <<<"$lines"
  done
}
check_ports
if command -v nginx >/dev/null; then
  nginx -t
  config check-nginx-domain --domain "$DOMAIN" --managed-path "$SITE_FILE"
fi
if [[ -L $SITE_FILE || -e $SITE_FILE ]]; then
  [[ ! -L $SITE_FILE ]] || die 'Refusing a symlinked managed Nginx site file.'
  head -n 1 "$SITE_FILE" | grep -q '^# Managed by Server Connector installer\.' || die 'The Nginx site filename is occupied by an unmanaged file.'
fi
if [[ -L $SITE_LINK ]]; then
  [[ $(readlink -f "$SITE_LINK") == "$SITE_FILE" ]] || die 'The Nginx enabled-site name belongs to another site.'
elif [[ -e $SITE_LINK ]]; then die 'The Nginx enabled-site path is not a managed symlink.'; fi

STAGE='preserve configuration and generate private settings'
[[ ! -L .installer && ! -L .installer/backups ]] || die 'Refusing a symlinked installer state directory.'
install -d -m 0700 .installer .installer/backups
BACKUP_DIR=$(mktemp -d "$PROJECT_DIR/.installer/backups/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
if [[ -e .env ]]; then [[ ! -L .env ]] || die 'Refusing a symlinked .env file.'; cp -a -- .env "$BACKUP_DIR/env"; ENV_EXISTED=1; fi
if [[ -e $SITE_FILE ]]; then cp -a -- "$SITE_FILE" "$BACKUP_DIR/nginx-site"; SITE_EXISTED=1; fi
if [[ -L $SITE_LINK ]]; then cp -a -- "$SITE_LINK" "$BACKUP_DIR/nginx-link"; LINK_EXISTED=1; fi
DATA_ARGS=()
if docker volume inspect server-connector_gateway_data >/dev/null 2>&1; then DATA_ARGS=(--has-data); fi
GATEWAY_ID=$(docker ps -aq --filter label=com.docker.compose.project=server-connector --filter label=com.docker.compose.service=gateway)
[[ $GATEWAY_ID != *$'\n'* ]] || die 'Multiple project gateway containers found.'
OWNED_PORT=
if [[ -n $GATEWAY_ID ]]; then
  OWNED_PORT=$(docker inspect --format '{{range (index .HostConfig.PortBindings "3080/tcp")}}{{if eq .HostIp "127.0.0.1"}}{{.HostPort}}{{end}}{{end}}' "$GATEWAY_ID")
fi
config prepare --domain "$DOMAIN" --email "$EMAIL" --cidrs "$SSH_CIDRS" --callbacks "$CALLBACKS" --owned-port "$OWNED_PORT" "${DATA_ARGS[@]}" >"$BACKUP_DIR/prepared.json"
DOMAIN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["domain"])' "$BACKUP_DIR/prepared.json")
LOCAL_PORT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["port"])' "$BACKUP_DIR/prepared.json")
SUBNET=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["subnet"])' "$BACKUP_DIR/prepared.json")
compose config --quiet

STAGE='build and start the gateway'
log 'Building the application image, running its tests and starting the gateway.'
compose build gateway
compose up -d --no-build --wait --wait-timeout 180 gateway
# Keep the original network definition compatible with existing Caddy installations,
# then verify Docker's actual bridge before trusting its forwarded client IPs.
docker network inspect server-connector_control --format '{{json .IPAM.Config}}' \
  | python3 -c 'import ipaddress,json,sys; network=ipaddress.ip_network(sys.argv[1]); assert any(row.get("Subnet")==str(network) and row.get("Gateway")==str(network.network_address+1) for row in json.load(sys.stdin)), "Unexpected Docker bridge address"' "$SUBNET"
curl -fsS --connect-timeout 5 --max-time 10 -H "Host: $DOMAIN" "http://127.0.0.1:$LOCAL_PORT/healthz" >/dev/null

STAGE='create the initial MFA administrator'
if compose exec -T gateway node dist/cli.js has-admin; then
  log 'An active MFA administrator already exists; accounts and passwords are preserved.'
else
  ADMIN_STATUS=$?
  [[ $ADMIN_STATUS == 3 ]] || die 'Cannot inspect administrator state; no account was reset.'
  prompt ADMIN_NAME 'Initial administrator username' admin
  [[ $ADMIN_NAME =~ ^[a-zA-Z0-9_.@-]{3,80}$ ]] || die 'Invalid administrator username.'
  log 'Set a private password, save the one-time MFA key and confirm a current code.'
  compose exec gateway node dist/cli.js create-admin "$ADMIN_NAME" </dev/tty >/dev/tty
fi

STAGE='install and configure Nginx and Certbot'
if [[ -n $CADDY_ID ]]; then
  log 'Moving this project from Caddy to host Nginx; other containers are preserved.'
  docker stop "$CADDY_ID" >/dev/null
  CADDY_STOPPED=1
fi
check_ports
apt-get install -y --no-remove nginx certbot
install -d -m 0755 /etc/nginx/sites-available /etc/nginx/sites-enabled /var/lib/server-connector/acme/.well-known/acme-challenge
config check-nginx-domain --domain "$DOMAIN" --managed-path "$SITE_FILE"
IPV6_ARGS=(--ipv4-only)
if [[ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 && $(</proc/sys/net/ipv6/conf/all/disable_ipv6) == 0 ]]; then IPV6_ARGS=(); fi
activate_site() {
  local mode=$1 temporary
  temporary=$(mktemp /etc/nginx/sites-available/.server-connector-XXXXXX)
  config render --mode "$mode" --domain "$DOMAIN" --port "$LOCAL_PORT" "${IPV6_ARGS[@]}" >"$temporary"
  chmod 0644 "$temporary"
  SITE_CHANGED=1
  mv -f -- "$temporary" "$SITE_FILE"
  ln -sfn -- "$SITE_FILE" "$SITE_LINK"
  nginx -t
  systemctl enable nginx
  if systemctl is-active --quiet nginx; then systemctl reload nginx; else systemctl start nginx; fi
}
CERTIFICATE_DIR="/etc/letsencrypt/live/server-connector-$DOMAIN"
if [[ -s $CERTIFICATE_DIR/fullchain.pem && -s $CERTIFICATE_DIR/privkey.pem ]]; then activate_site https; else activate_site http; fi

STAGE='open web ports on an already active host firewall'
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  ufw allow 80/tcp
  ufw allow 443/tcp
fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-service=http
  firewall-cmd --permanent --add-service=https
  firewall-cmd --add-service=http
  firewall-cmd --add-service=https
fi
# Never enable/reset a firewall or change SSH rules. Provider firewalls are external.
CHALLENGE_TOKEN=$(openssl rand -hex 16)
printf '%s' "$CHALLENGE_TOKEN" >"/var/lib/server-connector/acme/.well-known/acme-challenge/$CHALLENGE_TOKEN"
chmod 0644 "/var/lib/server-connector/acme/.well-known/acme-challenge/$CHALLENGE_TOKEN"
CHALLENGE_RESPONSE=$(curl -fsS --connect-timeout 5 --max-time 10 -H "Host: $DOMAIN" "http://127.0.0.1/.well-known/acme-challenge/$CHALLENGE_TOKEN")
rm -f -- "/var/lib/server-connector/acme/.well-known/acme-challenge/$CHALLENGE_TOKEN"
[[ $CHALLENGE_RESPONSE == "$CHALLENGE_TOKEN" ]] || die 'The local ACME challenge route is not served by the managed Nginx site.'

STAGE='issue HTTPS certificate and configure automatic renewal'
log 'Requesting or reusing a trusted HTTPS certificate.'
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
HOOK=/etc/letsencrypt/renewal-hooks/deploy/server-connector-nginx.sh
if [[ -e $HOOK || -L $HOOK ]]; then
  if [[ -L $HOOK ]] || ! grep -q '^# Managed by Server Connector installer\.' "$HOOK"; then
    die 'The certificate hook filename is occupied by an unmanaged file.'
  fi
fi
cat >"$HOOK" <<'HOOK'
#!/bin/sh
# Managed by Server Connector installer.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
nginx -t
systemctl reload nginx
HOOK
chmod 0755 "$HOOK"
certbot certonly --webroot --webroot-path /var/lib/server-connector/acme \
  --cert-name "server-connector-$DOMAIN" --domain "$DOMAIN" --email "$EMAIL" \
  --agree-tos --no-eff-email --non-interactive --keep-until-expiring
activate_site https
systemctl enable --now certbot.timer

STAGE='verify HTTPS, OAuth discovery and certificate renewal'
curl -fsS --connect-timeout 5 --max-time 15 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/healthz" >/dev/null
curl -fsS --connect-timeout 5 --max-time 15 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/.well-known/oauth-protected-resource/mcp" \
  | python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["resource"] == "https://"+sys.argv[1]+"/mcp"' "$DOMAIN"
certbot renew --cert-name "server-connector-$DOMAIN" --dry-run --non-interactive
COMMITTED=1
if ! curl -fsS --connect-timeout 10 --max-time 25 "https://$DOMAIN/healthz" >/dev/null; then
  die 'Local HTTPS and OAuth checks passed, but access using public DNS failed. The deployment was retained; check provider firewall/NAT/DNS and rerun.'
fi
printf 'nginx\n' >.installer/proxy-mode
log 'Installation completed.'
printf 'Custom MCP URL: https://%s/mcp\n' "$DOMAIN"
printf 'Add this URL in ChatGPT Custom MCP and sign in once using OAuth. No manual client ID or secret is needed.\n'
printf 'Panel: https://%s\n' "$DOMAIN"
printf 'Nginx/TLS renewal are configured. Save the master key separately from database backups.\n'
printf 'Private configuration backups: %s\n' "$BACKUP_DIR"
