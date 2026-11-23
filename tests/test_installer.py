"""Host installer regression tests. These never install packages or edit /etc."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("install_config", ROOT / "scripts" / "install_config.py")
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
DOMAIN = "connector.example.test"
EMAIL = "operator@example.test"
CIDRS = "10.20.0.10/32,10.20.0.11/32"
CALLBACK = "https://chatgpt.com/connector_platform_oauth_redirect"


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="connector-install-test-")
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def prepare(self, **kwargs):
        with patch.object(config, "choose_port", return_value=3087):
            return config.prepare(self.root, DOMAIN, EMAIL, CIDRS, CALLBACK, [], None, **kwargs)

    def test_shell_syntax_and_help_do_not_modify_host(self):
        subprocess.run(["bash", "-n", str(ROOT / "script.sh")], check=True)
        result = subprocess.run(["bash", str(ROOT / "script.sh"), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("sudo bash script.sh", result.stdout)

    def test_injection_and_unsafe_inputs_rejected_before_writes(self):
        invalid = [
            ("example.test;touch /tmp/pwn", EMAIL, CIDRS, CALLBACK),
            ("https://example.test", EMAIL, CIDRS, CALLBACK),
            (DOMAIN, "name$(command)@example.test", CIDRS, CALLBACK),
            (DOMAIN, EMAIL, "0.0.0.0/0", CALLBACK),
            (DOMAIN, EMAIL, "::/0", CALLBACK),
            (DOMAIN, EMAIL, CIDRS, "https://user:pass@example.test/cb"),
            (DOMAIN, EMAIL, CIDRS, "https://example.test/${MASTER_KEY}"),
            (DOMAIN, EMAIL, CIDRS, "https://example.test/*"),
            (DOMAIN, EMAIL, CIDRS, "http://example.test/cb"),
        ]
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError):
                config.prepare(self.root, *values, [], None)
        self.assertFalse((self.root / ".env").exists())
        self.assertFalse((self.root / "secrets").exists())

    def test_new_install_is_private_and_reruns_preserve_the_key(self):
        first = self.prepare()
        key = (self.root / "secrets/master_key").read_bytes()
        old = (self.root / ".env").read_bytes()
        self.assertEqual(len(config.base64.b64decode(key.strip())), 32)
        self.assertNotIn(key.strip(), json.dumps(first).encode())
        self.assertEqual(stat.S_IMODE((self.root / ".env").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.root / "secrets").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / "secrets/master_key").stat().st_mode), 0o644)
        self.prepare(has_data=True)
        self.assertEqual(key, (self.root / "secrets/master_key").read_bytes())
        self.assertEqual(old, (self.root / ".env").read_bytes())

    def test_missing_or_invalid_original_key_never_regenerates_over_existing_data(self):
        with self.assertRaisesRegex(ValueError, "original key"):
            self.prepare(has_data=True)
        self.assertFalse((self.root / "secrets/master_key").exists())
        directory = self.root / "secrets"
        directory.mkdir()
        (directory / "master_key").write_text("invalid-original-key")
        with self.assertRaisesRegex(ValueError, "invalid"):
            self.prepare(has_data=True)
        self.assertEqual((directory / "master_key").read_text(), "invalid-original-key")

    def test_existing_env_master_key_is_imported_without_rotation(self):
        import base64
        key = base64.b64encode(b"a" * 32).decode()
        (self.root / ".env").write_text(f"MASTER_KEY='{key}'\nRETENTION_DAYS=17\nUNRELATED=value\n")
        self.prepare(has_data=True)
        self.assertEqual((self.root / "secrets/master_key").read_text().strip(), key)
        current = (self.root / ".env").read_text()
        self.assertNotIn(key, current)
        self.assertIn("RETENTION_DAYS=17", current)
        self.assertIn("UNRELATED=value", current)

    def test_dotenv_is_data_and_cannot_execute_commands(self):
        target = self.root / "should-not-exist"
        (self.root / ".env").write_text(f"UNRELATED=$(touch {target})\n")
        self.prepare()
        self.assertFalse(target.exists())
        result = subprocess.run(["python3", str(ROOT / "scripts/install_config.py"), "--root", str(self.root), "get", "MASTER_KEY"], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_symlinks_cannot_redirect_private_configuration_writes(self):
        original = self.root / "original"
        original.write_text("unchanged")
        (self.root / ".env").symlink_to(original)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.prepare()
        self.assertEqual(original.read_text(), "unchanged")
        (self.root / ".env").unlink()
        (self.root / "secrets").mkdir()
        (self.root / "secrets/master_key").symlink_to(original)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.prepare()
        self.assertEqual(original.read_text(), "unchanged")

    def test_network_selection_avoids_lan_vpn_and_other_docker_routes(self):
        occupied = [ipaddress.ip_network("172.31.0.0/16"), ipaddress.ip_network("10.0.0.0/8")]
        network = config.select_network({}, occupied, None, CIDRS)
        self.assertEqual(network["CONNECTOR_SUBNET"], "172.30.250.0/29")
        self.assertEqual(network["CONNECTOR_BRIDGE_IP"], "172.30.250.1")
        existing = (ipaddress.ip_network(network["CONNECTOR_SUBNET"]), network["CONNECTOR_BRIDGE_IP"])
        self.assertEqual(config.select_network(network, occupied, existing, CIDRS), network)
        with self.assertRaises(ValueError):
            config.select_network({"CONNECTOR_SUBNET": "172.31.250.0/29"}, occupied, None, CIDRS)
        with self.assertRaises(ValueError):
            config.select_network({}, [], existing, "172.30.0.0/16")

    def test_busy_ports_are_not_hijacked_and_owned_ports_can_be_reused(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            port = server.getsockname()[1]
            with self.assertRaises(ValueError):
                config.choose_port(str(port), "")
            self.assertEqual(config.choose_port(str(port), str(port)), port)

    def test_local_development_database_is_not_silently_replaced(self):
        (self.root / "data").mkdir()
        database = self.root / "data/connector.sqlite"
        database.write_bytes(b"local-db")
        with self.assertRaisesRegex(ValueError, "migrate"):
            self.prepare()
        self.assertEqual(database.read_bytes(), b"local-db")

    def test_nginx_templates_preserve_mcp_paths_and_forward_only_trusted_ip(self):
        https = config.render(ROOT, "https", DOMAIN, 3087)
        self.assertIn("proxy_pass http://127.0.0.1:3087;", https)
        self.assertIn("proxy_set_header Host $host;", https)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", https)
        self.assertNotIn("$proxy_add_x_forwarded_for", https)
        self.assertIn("proxy_buffering off;", https)
        self.assertIn("TLSv1.2 TLSv1.3", https)
        self.assertNotIn("@@", https)
        http = config.render(ROOT, "http", DOMAIN, 3087)
        self.assertNotIn("proxy_pass", http)
        self.assertIn("return 503", http)
        self.assertIn("/.well-known/acme-challenge/", http)
        self.assertNotIn("[::]", config.render(ROOT, "https", DOMAIN, 3087, ipv4_only=True))

    def test_docker_versions_with_known_loopback_isolation_issues_are_rejected(self):
        for version in ["27.5.1", "28.2.0", "28.3.2", "unknown", "29.1.0-rc1"]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                config.check_docker(version)
        for version in ["28.3.3", "29.1.0", "29.10.0", "29.1.0+vendor"]:
            config.check_docker(version)

    def test_other_nginx_sites_are_preserved_and_exact_domain_conflicts_rejected(self):
        available = self.root / "sites-available"
        available.mkdir()
        other = available / "unrelated"
        content = f"server {{ server_name {DOMAIN}; }}"
        other.write_text(content)
        own = available / "server-connector.conf"
        with self.assertRaisesRegex(ValueError, "another Nginx"):
            config.check_nginx_domain(self.root, DOMAIN, own)
        self.assertEqual(other.read_text(), content)
        other.write_text("server { server_name unrelated.example.test; }")
        own.write_text(f"server {{ server_name {DOMAIN}; }}")
        enabled = self.root / "sites-enabled"
        enabled.mkdir()
        (enabled / "server-connector.conf").symlink_to(own)
        config.check_nginx_domain(self.root, DOMAIN, own)


if __name__ == "__main__":
    unittest.main()
