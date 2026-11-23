"""Exercise real CLI enrollment in an isolated PTY without logging test credentials."""
import base64
import hashlib
import hmac
import json
import os
import pty
import re
import secrets
import select
import sqlite3
import struct
import subprocess
import tempfile
import time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="connector-cli-qa-") as directory:
    env = dict(os.environ, NODE_ENV="test", PUBLIC_URL="http://127.0.0.1:3080",
               MASTER_KEY=base64.b64encode(os.urandom(32)).decode(), MASTER_KEY_FILE="",
               SSH_ALLOWED_CIDRS="127.0.0.1/32", REQUIRE_MFA="true",
               DATABASE_PATH=str(Path(directory) / "source.sqlite"))
    missing = subprocess.run(["node", "dist/cli.js", "has-admin"], env=env, cwd=root,
                             capture_output=True, timeout=10)
    assert missing.returncode == 3, "A new database reported an existing administrator"
    master, slave = pty.openpty()
    child = subprocess.Popen(["node", "dist/cli.js", "create-admin", "cli_qa_admin"],
                             stdin=slave, stdout=slave, stderr=slave, env=env,
                             cwd=root, start_new_session=True)
    os.close(slave)
    captured = b""

    def until(marker):
        global captured
        deadline = time.monotonic() + 10
        while marker not in captured:
            if time.monotonic() > deadline:
                raise RuntimeError("CLI prompt timed out")
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    captured += os.read(master, 65536)
                except OSError:
                    break
        if marker not in captured:
            raise RuntimeError("CLI exited before expected prompt")

    try:
        until(b"hidden): ")
        password = ("qa-only-" + secrets.token_hex(16)).encode()
        os.write(master, password + b"\r")
        until(b"Repeat password: ")
        os.write(master, password + b"\r")
        until(b"confirm enrollment: ")
        seed = re.search(rb"shown once\): ([A-Z2-7]{32})", captured).group(1)
        step = int(time.time() // 30)
        mac = hmac.new(base64.b32decode(seed), struct.pack(">Q", step), hashlib.sha1).digest()
        offset = mac[-1] & 15
        code = str((struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)
        os.write(master, code.encode() + b"\r")
        until(b"Account saved.")
        assert child.wait(timeout=10) == 0, "Enrollment failed"
        assert password not in captured, "Password was echoed"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        os.close(master)

    with sqlite3.connect(env["DATABASE_PATH"]) as database:
        row = database.execute("SELECT role,password_hash,totp_cipher FROM users").fetchone()
        assert row[0] == "admin" and row[1].startswith("scrypt$") and seed.decode() not in row[2]
    present = subprocess.run(["node", "dist/cli.js", "has-admin"], env=env, cwd=root,
                             capture_output=True, timeout=10)
    assert present.returncode == 0, "The confirmed MFA administrator was not recognized"
    backup = str(Path(directory) / "backup.sqlite")
    result = subprocess.run(["node", "dist/cli.js", "backup", backup], env=env, cwd=root,
                            capture_output=True, timeout=10)
    assert result.returncode == 0 and Path(backup).is_file(), "Backup failed"
    retry = subprocess.run(["node", "dist/cli.js", "backup", backup], env=env, cwd=root,
                           capture_output=True, timeout=10)
    assert retry.returncode != 0, "Backup overwrote an existing file"
    verified = subprocess.run(["node", "dist/cli.js", "verify-audit"], env=env, cwd=root,
                              capture_output=True, timeout=10)
    assert verified.returncode == 0 and json.loads(verified.stdout)["valid"], "Audit verification failed"
    with sqlite3.connect(backup) as database:
        assert database.execute("SELECT count(*) FROM users").fetchone()[0] == 1
    print("CLI smoke passed: hidden password, confirmed MFA enrollment, persistent account, encrypted MFA seed, online backup, overwrite prevention, audit verification.")
