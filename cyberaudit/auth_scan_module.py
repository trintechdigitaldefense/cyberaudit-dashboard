"""Authenticated scanning — SSH / WinRM / SMB credentialed checks.

Phase 2 feature #5. Credentials come ONLY from the job payload or environment.
Never hard-code secrets. ROE must authorise credentialed checks.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
from typing import Any

logger = logging.getLogger("CyberAuditDashboard")


def _creds_from_job(job: dict | None) -> dict[str, str]:
    job = job or {}
    env = os.environ

    def pick(*keys: str) -> str:
        for k in keys:
            v = (job.get(k) or env.get(k) or "").strip()
            if v:
                return v
        return ""

    return {
        "ssh_user": pick("ssh_user", "CYBERAUDIT_SSH_USER"),
        "ssh_password": pick("ssh_password", "CYBERAUDIT_SSH_PASSWORD"),
        "ssh_key": pick("ssh_key", "CYBERAUDIT_SSH_KEY"),
        "smb_user": pick("smb_user", "CYBERAUDIT_SMB_USER"),
        "smb_password": pick("smb_password", "CYBERAUDIT_SMB_PASSWORD"),
        "smb_domain": pick("smb_domain", "CYBERAUDIT_SMB_DOMAIN"),
        "winrm_user": pick("winrm_user", "CYBERAUDIT_WINRM_USER"),
        "winrm_password": pick("winrm_password", "CYBERAUDIT_WINRM_PASSWORD"),
    }


def _has_ssh_creds(c: dict) -> bool:
    return bool(c["ssh_user"] and (c["ssh_password"] or c["ssh_key"]))


def _has_smb_creds(c: dict) -> bool:
    return bool(c["smb_user"] and c["smb_password"])


def _has_winrm_creds(c: dict) -> bool:
    return bool(c["winrm_user"] and c["winrm_password"])


def _ssh_keyscan(host: str) -> str:
    try:
        r = subprocess.run(
            ["ssh-keyscan", "-T", "3", "-t", "rsa,ecdsa,ed25519", host],
            capture_output=True, text=True, timeout=8,
        )
        return (r.stdout or "").strip()[:500]
    except Exception:
        return ""


def check_ssh_host(host: str, creds: dict) -> list[dict]:
    findings: list[dict] = []
    keys = _ssh_keyscan(host)
    if not keys:
        findings.append({
            "host": host, "port": "22", "severity": "info",
            "title": "SSH host key not retrieved (filtered or down)",
            "cve": "", "cma_section": "Section 7", "service": "ssh",
            "evidence": "ssh-keyscan empty",
        })
    try:
        import paramiko  # type: ignore
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kw: dict[str, Any] = {
            "hostname": host, "username": creds["ssh_user"], "timeout": 8,
            "allow_agent": False, "look_for_keys": False,
        }
        if creds["ssh_key"]:
            connect_kw["key_filename"] = creds["ssh_key"]
        else:
            connect_kw["password"] = creds["ssh_password"]
        client.connect(**connect_kw)
        stdin, stdout, stderr = client.exec_command(
            "id; uname -a; grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' "
            "/etc/ssh/sshd_config 2>/dev/null | head -20", timeout=10,
        )
        out = (stdout.read() or b"").decode("utf-8", errors="replace")
        client.close()
        evidence = out[:1500]
        if "PermitRootLogin yes" in evidence:
            findings.append({
                "host": host, "port": "22", "severity": "high",
                "title": "SSH PermitRootLogin is enabled",
                "cve": "", "cma_section": "Section 3", "service": "ssh", "evidence": evidence,
            })
        if "PasswordAuthentication yes" in evidence:
            findings.append({
                "host": host, "port": "22", "severity": "medium",
                "title": "SSH password authentication enabled",
                "cve": "", "cma_section": "Section 3", "service": "ssh", "evidence": evidence,
            })
        if evidence.startswith("uid=0(") or "\nuid=0(" in evidence:
            findings.append({
                "host": host, "port": "22", "severity": "high",
                "title": "Authenticated SSH session is root — reduce privilege",
                "cve": "", "cma_section": "Section 3", "service": "ssh",
                "evidence": evidence.split("\n")[0][:200],
            })
        if not any(f.get("severity") in ("high", "critical", "medium") for f in findings):
            findings.append({
                "host": host, "port": "22", "severity": "info",
                "title": "SSH authentication succeeded — review hardening baseline",
                "cve": "", "cma_section": "Section 7", "service": "ssh",
                "evidence": evidence[:400] or "login ok",
            })
    except ImportError:
        findings.append({
            "host": host, "port": "22", "severity": "info",
            "title": "SSH credentials supplied but paramiko not installed — limited check",
            "cve": "", "cma_section": "Section 7", "service": "ssh",
            "evidence": "pip install paramiko for full authenticated SSH checks",
        })
    except Exception as exc:
        findings.append({
            "host": host, "port": "22", "severity": "medium",
            "title": "SSH authentication failed with provided credentials",
            "cve": "", "cma_section": "Section 3", "service": "ssh",
            "evidence": str(exc)[:300],
        })
    return findings


def check_smb_host(host: str, creds: dict) -> list[dict]:
    findings: list[dict] = []
    try:
        r = subprocess.run(["smbclient", "-L", f"//{host}", "-N", "-g"],
                           capture_output=True, text=True, timeout=12)
        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode == 0 and ("Disk|" in out or "IPC$" in out):
            findings.append({
                "host": host, "port": "445", "severity": "high",
                "title": "SMB null session / anonymous share listing possible",
                "cve": "", "cma_section": "Section 3", "service": "smb", "evidence": out[:800],
            })
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.debug("smb null probe: %s", exc)

    user = creds["smb_user"]
    if creds["smb_domain"]:
        user = f"{creds['smb_domain']}\\{user}"
    try:
        r = subprocess.run(
            ["smbclient", "-L", f"//{host}", "-U", f"{user}%{creds['smb_password']}", "-g"],
            capture_output=True, text=True, timeout=15,
        )
        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode == 0:
            if "ADMIN$" in out or "C$" in out:
                findings.append({
                    "host": host, "port": "445", "severity": "medium",
                    "title": "SMB administrative shares visible to credentialed user",
                    "cve": "", "cma_section": "Section 6", "service": "smb", "evidence": out[:800],
                })
            elif not findings:
                findings.append({
                    "host": host, "port": "445", "severity": "info",
                    "title": "SMB authentication succeeded — review share permissions",
                    "cve": "", "cma_section": "Section 7", "service": "smb", "evidence": out[:500],
                })
        else:
            findings.append({
                "host": host, "port": "445", "severity": "low",
                "title": "SMB authentication failed or restricted",
                "cve": "", "cma_section": "Section 7", "service": "smb", "evidence": out[:300],
            })
    except FileNotFoundError:
        findings.append({
            "host": host, "port": "445", "severity": "info",
            "title": "SMB credentials supplied but smbclient not installed",
            "cve": "", "cma_section": "Section 7", "service": "smb",
            "evidence": "Install smbclient for authenticated share enumeration",
        })
    except Exception as exc:
        findings.append({
            "host": host, "port": "445", "severity": "low",
            "title": "SMB credentialed check error",
            "cve": "", "cma_section": "Section 7", "service": "smb", "evidence": str(exc)[:300],
        })
    return findings


def check_winrm_host(host: str, port: int, creds: dict) -> list[dict]:
    findings: list[dict] = []
    try:
        with socket.create_connection((host, port), timeout=5):
            pass
    except Exception as exc:
        return [{
            "host": host, "port": str(port), "severity": "info",
            "title": "WinRM port not reachable during auth check",
            "cve": "", "cma_section": "Section 7", "service": "rdp", "evidence": str(exc)[:200],
        }]
    try:
        import winrm  # type: ignore
        protocol = "http" if port == 5985 else "https"
        url = f"{protocol}://{host}:{port}/wsman"
        session = winrm.Session(url, auth=(creds["winrm_user"], creds["winrm_password"]),
                                transport="ntlm", server_cert_validation="ignore")
        r = session.run_cmd("whoami")
        out = (r.std_out or b"").decode("utf-8", errors="replace")
        if r.status_code == 0:
            findings.append({
                "host": host, "port": str(port), "severity": "high",
                "title": "WinRM authentication succeeded — management plane exposed",
                "cve": "", "cma_section": "Section 3", "service": "rdp",
                "evidence": f"whoami={out.strip()[:200]}",
            })
        else:
            findings.append({
                "host": host, "port": str(port), "severity": "medium",
                "title": "WinRM reachable but command failed with supplied credentials",
                "cve": "", "cma_section": "Section 3", "service": "rdp",
                "evidence": (r.std_err or b"").decode("utf-8", errors="replace")[:300],
            })
    except ImportError:
        findings.append({
            "host": host, "port": str(port), "severity": "info",
            "title": "WinRM open — install pywinrm for authenticated checks",
            "cve": "", "cma_section": "Section 7", "service": "rdp",
            "evidence": "pip install pywinrm",
        })
    except Exception as exc:
        findings.append({
            "host": host, "port": str(port), "severity": "medium",
            "title": "WinRM authentication failed with provided credentials",
            "cve": "", "cma_section": "Section 3", "service": "rdp",
            "evidence": str(exc)[:300],
        })
    return findings


def run_authenticated_checks(open_ports: list[dict], job: dict | None = None) -> list[dict]:
    creds = _creds_from_job(job)
    if not (_has_ssh_creds(creds) or _has_smb_creds(creds) or _has_winrm_creds(creds)):
        return []
    findings: list[dict] = []
    ssh_hosts = {r["host"] for r in open_ports if str(r.get("port")) == "22"}
    smb_hosts = {r["host"] for r in open_ports if str(r.get("port")) in ("445", "139")}
    winrm_rows = [r for r in open_ports if str(r.get("port")) in ("5985", "5986")]
    if _has_ssh_creds(creds):
        for host in sorted(ssh_hosts):
            findings.extend(check_ssh_host(host, creds))
    if _has_smb_creds(creds):
        for host in sorted(smb_hosts):
            findings.extend(check_smb_host(host, creds))
    if _has_winrm_creds(creds):
        for row in winrm_rows:
            findings.extend(check_winrm_host(row["host"], int(row["port"]), creds))
    return findings
