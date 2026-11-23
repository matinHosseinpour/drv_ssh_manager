"""Validate rendered templates using a real nginx binary, without starting a server."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("install_config", root / "scripts/install_config.py")
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
binary = os.environ.get("NGINX_BINARY") or shutil.which("nginx")
if not binary:
    raise SystemExit("Set NGINX_BINARY to an installed nginx executable for this optional integration check.")
with tempfile.TemporaryDirectory(prefix="connector-nginx-syntax-") as directory:
    scratch = Path(directory)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(scratch / "privkey.pem"),
                    "-out", str(scratch / "fullchain.pem"), "-days", "1", "-subj", "/CN=connector.example.test"],
                   check=True, capture_output=True)
    for mode in ("http", "https"):
        rendered = config.render(root, mode, "connector.example.test", 3087)
        rendered = rendered.replace("/var/log/nginx/server-connector.error.log", str(scratch / "site-error.log"))
        rendered = rendered.replace("/etc/letsencrypt/live/server-connector-connector.example.test/", str(scratch) + "/")
        site = scratch / "site.conf"
        site.write_text(rendered)
        main = scratch / "nginx.conf"
        main.write_text(f'pid "{scratch}/nginx.pid";\nerror_log "{scratch}/error.log";\nevents {{}}\nhttp {{ include "{site}"; }}\n')
        subprocess.run([binary, "-t", "-p", directory + "/", "-e", "stderr", "-c", str(main)], check=True)
    print("Real nginx syntax passed for the ACME bootstrap and HTTPS proxy templates; no web service was started.")
