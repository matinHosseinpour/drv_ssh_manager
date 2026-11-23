"""Installer configuration helpers. No dotenv evaluation, shell execution or key output."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
from urllib.parse import urlsplit

MANAGED = "# Managed by Server Connector installer."
PUBLIC_KEYS = {"GATEWAY_DOMAIN", "ACME_EMAIL", "SSH_ALLOWED_CIDRS", "OAUTH_REDIRECT_URIS", "ACME_TERMS_ACCEPTED"}


def read_env(path):
    if not path.exists():
        return {}, []
    if path.is_symlink():
        raise ValueError("Refusing a symlinked .env file")
    lines = path.read_text().splitlines()
    values = {}
    for line in lines:
        match = re.fullmatch(r"\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)", line)
        if match:
            value = match[2].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[match[1]] = value
    return values, lines


def validate(domain, email, cidrs, callbacks):
    domain = domain.lower()
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels):
        raise ValueError("Use a DNS hostname, without scheme, path, wildcard or port")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("A domain name is required for the public HTTPS certificate")
    if not re.fullmatch(r"[A-Za-z0-9.!_+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", email):
        raise ValueError("Enter a valid certificate contact email")
    networks = []
    for value in cidrs.split(","):
        network = ipaddress.ip_network(value.strip(), strict=False)
        if network.prefixlen == 0:
            raise ValueError("Default-route SSH allowlists are forbidden")
        networks.append(str(network))
    uris = [uri.strip() for uri in callbacks.split(",")]
    if not 1 <= len(uris) <= 10:
        raise ValueError("Use between 1 and 10 exact OAuth callbacks")
    for uri in uris:
        parsed = urlsplit(uri)
        if len(uri) > 2048 or any(char.isspace() or char in "$#'\"`\\*" for char in uri) or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("OAuth callbacks must be exact HTTPS URLs without credentials or wildcards")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("Invalid callback port")
    return domain, email, ",".join(networks), ",".join(uris)


def atomic_write(path, content, mode):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing to replace a symlink")
    fd, temporary = tempfile.mkstemp(prefix=".connector-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def system_networks():
    routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route", "show"], timeout=20))
    occupied = [ipaddress.ip_network(row["dst"], strict=False) for row in routes if row.get("dst") not in (None, "default")]
    ids = subprocess.check_output(["docker", "network", "ls", "-q"], timeout=20).decode().split()
    inspected = json.loads(subprocess.check_output(["docker", "network", "inspect", *ids], timeout=20)) if ids else []
    own = None
    for network in inspected:
        for config in network.get("IPAM", {}).get("Config", []) or []:
            if config.get("Subnet"):
                value = ipaddress.ip_network(config["Subnet"])
                if value.version == 4:
                    occupied.append(value)
                    if network["Name"] == "server-connector_control":
                        own = (value, config.get("Gateway"))
    return occupied, own


def select_network(values, occupied, own, ssh_cidrs):
    forbidden = occupied + [ipaddress.ip_network(value) for value in ssh_cidrs.split(",") if ":" not in value]
    requested = values.get("CONNECTOR_SUBNET")
    if own:
        subnet, gateway = own
        if requested and ipaddress.ip_network(requested) != subnet:
            raise ValueError("An existing project network differs from CONNECTOR_SUBNET; preserve its subnet")
        if gateway and gateway != str(subnet.network_address + 1):
            raise ValueError("Existing project network has an unexpected bridge address")
    elif requested:
        subnet = ipaddress.ip_network(requested)
        if any(subnet.overlaps(network) for network in forbidden):
            raise ValueError("Configured Docker subnet overlaps a route, target network or other Docker network")
    else:
        subnet = next((ipaddress.ip_network(value) for value in ["172.31.250.0/29", "172.30.250.0/29", "10.254.250.0/29", "192.168.250.0/29"]
                       if not any(ipaddress.ip_network(value).overlaps(network) for network in forbidden)), None)
        if subnet is None:
            raise ValueError("No non-overlapping Docker subnet found; choose CONNECTOR_SUBNET in .env")
    if subnet.version != 4 or subnet.prefixlen != 29:
        raise ValueError("The managed Docker network must be an IPv4 /29")
    if any(subnet.overlaps(ipaddress.ip_network(value)) for value in ssh_cidrs.split(",") if ":" not in value):
        raise ValueError("Docker subnet overlaps an SSH target allowlist")
    return {"CONNECTOR_SUBNET": str(subnet), "CONNECTOR_BRIDGE_IP": str(subnet.network_address + 1),
            "CONNECTOR_CADDY_IP": str(subnet.network_address + 2), "CONNECTOR_APP_IP": str(subnet.network_address + 3)}


def choose_port(existing, owned_port):
    candidates = [int(existing)] if existing else list(range(3080, 3100))
    for port in candidates:
        if not 1024 <= port <= 65535:
            raise ValueError("The local gateway port must be between 1024 and 65535")
        if owned_port and port == int(owned_port):
            return port
        try:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", port))
            return port
        except OSError:
            pass
    raise ValueError("The configured gateway port is busy; use a free GATEWAY_HTTP_PORT")


def prepare(root, domain, email, cidrs, callbacks, occupied, own, owned_port="", has_data=False):
    root = Path(root)
    domain, email, cidrs, callbacks = validate(domain, email, cidrs, callbacks)
    values, lines = read_env(root / ".env")
    if (root / "data" / "connector.sqlite").exists() and not has_data:
        raise ValueError("Local-development database found; migrate it explicitly before container installation")
    updates = {"GATEWAY_DOMAIN": domain, "ACME_EMAIL": email, "SSH_ALLOWED_CIDRS": cidrs,
               "OAUTH_REDIRECT_URIS": callbacks, "ACME_TERMS_ACCEPTED": "1"}
    updates.update(select_network(values, occupied, own, cidrs))
    updates["GATEWAY_HTTP_PORT"] = str(choose_port(values.get("GATEWAY_HTTP_PORT"), owned_port))
    directory = root / "secrets"
    if directory.is_symlink():
        raise ValueError("Refusing a symlinked secrets directory")
    key_path = directory / "master_key"
    if key_path.is_symlink():
        raise ValueError("Refusing a symlinked master key")
    if key_path.exists():
        key = key_path.read_text().strip()
    elif values.get("MASTER_KEY"):
        key = values["MASTER_KEY"]
    elif has_data:
        raise ValueError("Existing data volume found but master key is missing; restore the original key")
    else:
        key = base64.b64encode(secrets.token_bytes(32)).decode()
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", key) or len(base64.b64decode(key, validate=True)) != 32:
        raise ValueError("Existing master key is invalid; it has not been replaced")
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    # Compose file-backed secrets preserve source mode; enclosing host directory stays private.
    if not key_path.exists():
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w") as stream:
            stream.write(key + "\n")
    key_path.chmod(0o644)
    kept = [line for line in lines if not (match := re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)=", line)) or match[1] not in updates and match[1] not in {"MASTER_KEY", "MASTER_KEY_FILE"}]
    content = "\n".join(kept + [f"{key}={value}" for key, value in updates.items()]) + "\n"
    atomic_write(root / ".env", content, 0o600)
    return {"domain": domain, "port": int(updates["GATEWAY_HTTP_PORT"]), "subnet": updates["CONNECTOR_SUBNET"]}


def check_docker(version):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+][A-Za-z0-9.+_-]+)?", version)
    if not match or re.search(r"-(?:rc|alpha|beta|dev)", version) or tuple(map(int, match.group(1, 2, 3))) < (28, 3, 3):
        raise ValueError("Docker Engine 28.3.3 or newer is required for private loopback port publishing; existing workloads were not upgraded or removed")


def render(root, mode, domain, port, ipv4_only=False):
    validate(domain, "installer@example.com", "10.0.0.1/32", "https://chatgpt.com/connector_platform_oauth_redirect")
    if not 1024 <= int(port) <= 65535:
        raise ValueError("Invalid upstream port")
    template = (Path(root) / "deploy" / f"nginx-{mode}.conf.in").read_text()
    output = template.replace("@@DOMAIN@@", domain).replace("@@PORT@@", str(port))
    return re.sub(r"^    listen \[::\]:.*\n", "", output, flags=re.M) if ipv4_only else output


def check_nginx_domain(config_root, domain, managed_path):
    root, allowed = Path(config_root), Path(managed_path).resolve()
    paths = set(root.rglob("*.conf"))
    for directory in (root / "sites-enabled", root / "sites-available"):
        if directory.exists():
            paths.update(directory.iterdir())
    for path in paths:
        if not path.is_file() or path.resolve() == allowed:
            continue
        text = re.sub(r"#.*", "", path.read_text(errors="replace"))
        if any(domain in clause.split() for clause in re.findall(r"\bserver_name\s+([^;]+);", text)):
            raise ValueError("This domain already belongs to another Nginx site; refusing to replace it")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    commands = parser.add_subparsers(dest="command", required=True)
    get = commands.add_parser("get")
    get.add_argument("key", choices=sorted(PUBLIC_KEYS))
    for name in ("validate", "prepare"):
        command = commands.add_parser(name)
        for flag in ("domain", "email", "cidrs", "callbacks"):
            command.add_argument("--" + flag, required=True)
        if name == "prepare":
            command.add_argument("--owned-port", default="")
            command.add_argument("--has-data", action="store_true")
    command = commands.add_parser("render")
    command.add_argument("--mode", choices=("http", "https"), required=True)
    command.add_argument("--domain", required=True)
    command.add_argument("--port", type=int, required=True)
    command.add_argument("--ipv4-only", action="store_true")
    command = commands.add_parser("check-docker")
    command.add_argument("version")
    command = commands.add_parser("check-nginx-domain")
    command.add_argument("--config-root", type=Path, default=Path("/etc/nginx"))
    command.add_argument("--domain", required=True)
    command.add_argument("--managed-path", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "get":
        value = read_env(args.root / ".env")[0].get(args.key, "")
        if "\n" in value or "\r" in value:
            raise ValueError("Invalid configuration line")
        print(value)
    elif args.command == "validate":
        validate(args.domain, args.email, args.cidrs, args.callbacks)
    elif args.command == "prepare":
        occupied, own = system_networks()
        print(json.dumps(prepare(args.root, args.domain, args.email, args.cidrs, args.callbacks, occupied, own, args.owned_port, args.has_data)))
    elif args.command == "render":
        print(render(args.root, args.mode, args.domain, args.port, args.ipv4_only), end="")
    elif args.command == "check-docker":
        check_docker(args.version)
    elif args.command == "check-nginx-domain":
        check_nginx_domain(args.config_root, args.domain, args.managed_path)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        import sys
        print(f"Installer configuration: {error}", file=sys.stderr)
        sys.exit(1)
    except (OSError, subprocess.SubprocessError):
        # Never print parsed dotenv values, key material, subprocess output or request bodies.
        import sys
        print("Installer configuration failed: invalid input, conflicting network/site, missing original key or unavailable local Docker. Check the supplied settings and existing installation.", file=sys.stderr)
        sys.exit(1)
