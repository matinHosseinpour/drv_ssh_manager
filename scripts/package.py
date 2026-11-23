"""Build a source-only archive from an explicit allowlist; never include runtime data."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import hashlib

root = Path(__file__).resolve().parents[1]
out = root / "artifacts" / "server-connector.zip"
out.parent.mkdir(exist_ok=True)
names = ["package.json", "package-lock.json", "tsconfig.json", ".env.example", ".gitignore", ".dockerignore", "Dockerfile", "compose.yaml", "README.md", "script.sh"]
files = [root / name for name in names]
for folder in ["src", "public", "tests", "deploy", "docs", "scripts", ".github"]:
    files.extend(path for path in (root / folder).rglob("*") if path.is_file() and "__pycache__" not in path.parts)
with ZipFile(out, "w", ZIP_DEFLATED) as archive:
    for path in sorted(files):
        archive.write(path, "server-connector/" + path.relative_to(root).as_posix())
with ZipFile(out) as archive:
    assert archive.testzip() is None
    assert len(archive.namelist()) == len(files)
    assert not any("node_modules/" in name or "/secrets/" in name or name.endswith("/.env") or "/data/" in name for name in archive.namelist())
print(f"{out.name}: {len(files)} files, {out.stat().st_size} bytes")
print("SHA256", hashlib.sha256(out.read_bytes()).hexdigest())
