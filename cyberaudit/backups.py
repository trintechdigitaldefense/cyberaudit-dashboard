"""C1 — Automated encrypted backups with tested-restore."""
from __future__ import annotations
import json, logging, shutil, tarfile, tempfile
from datetime import datetime
from pathlib import Path
from typing import Any
from cyberaudit import config
logger = logging.getLogger("CyberAuditDashboard")

def backup_root() -> Path:
    root = config.DATA_DIR / "backups"
    root.mkdir(parents=True, exist_ok=True)
    return root

def run_backup(*, encrypt: bool = True) -> dict[str, Any]:
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    staging = Path(tempfile.mkdtemp(prefix="ca-bak-"))
    try:
        for label, src in [("cyber_audit.db", config.DB_PATH), ("audit_log.db", config.DATA_DIR / "audit_log.db"),
                           ("benchmarks.db", config.DATA_DIR / "benchmarks.db"), ("reports", config.REPORTS_DIR)]:
            if not src.exists(): continue
            dest = staging / label
            if src.is_dir(): shutil.copytree(src, dest, dirs_exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
        tar_path = backup_root() / f"cyberaudit_backup_{ts}.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            for p in staging.iterdir():
                tar.add(p, arcname=p.name)
        result = {"status": "ok", "path": str(tar_path), "bytes": tar_path.stat().st_size, "encrypted": False, "created_at": ts}
        if encrypt:
            try:
                from cyberaudit.encryption import get_data_key, encrypt_file
                if get_data_key():
                    cae = encrypt_file(tar_path, delete_plaintext=True)
                    result.update(path=str(cae), encrypted=True, bytes=cae.stat().st_size)
                else:
                    result["encrypt_note"] = "CYBERAUDIT_DATA_KEY not set"
            except Exception as exc:
                result["encrypt_note"] = str(exc)[:200]
        manifest = backup_root() / f"cyberaudit_backup_{ts}.json"
        manifest.write_text(json.dumps(result, indent=2), encoding="utf-8")
        result["manifest"] = str(manifest)
        return result
    finally:
        shutil.rmtree(staging, ignore_errors=True)

def test_restore(backup_path: Path, dest: Path | None = None) -> dict[str, Any]:
    dest = dest or Path(tempfile.mkdtemp(prefix="ca-restore-"))
    dest.mkdir(parents=True, exist_ok=True)
    path = Path(backup_path)
    if str(path).endswith(".cae"):
        from cyberaudit.encryption import decrypt_file
        plain = dest / "restored.tar.gz"
        decrypt_file(path, plain)
        path = plain
    with tarfile.open(path, "r:gz") as tar:
        tar.extractall(dest)
    members = [p.name for p in dest.iterdir()]
    ok = bool(members)
    return {"status": "ok" if ok else "incomplete", "dest": str(dest), "members": members}
