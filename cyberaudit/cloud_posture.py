"""P6.3 — Cloud posture (AWS/Azure snapshot JSON). Add-on module."""
from __future__ import annotations
import json
from pathlib import Path
ADMIN_PORTS = {22, 3389, 3306, 1433, 5432, 27017, 6379, 445, 5985, 5986}

def _load_snapshot(job: dict) -> dict:
    raw = job.get("cloud_snapshot")
    if isinstance(raw, dict): return raw
    if isinstance(raw, str) and raw.strip().startswith("{"): return json.loads(raw)
    path = job.get("cloud_snapshot_file") or ""
    if path and Path(path).is_file(): return json.loads(Path(path).read_text(encoding="utf-8"))
    return {}

def assess_aws(snapshot: dict) -> list[dict]:
    findings = []
    for bucket in snapshot.get("s3_buckets") or snapshot.get("buckets") or []:
        name = bucket.get("name") or bucket.get("Name") or "bucket"
        if bucket.get("public") or bucket.get("is_public") or bucket.get("acl") == "public-read":
            findings.append({
                "host": f"s3://{name}", "port": "cloud", "severity": "critical",
                "title": f"Public cloud storage bucket: {name}", "cve": "", "cma_section": "Section 3",
                "service": "cloud_s3", "evidence": json.dumps(bucket)[:800], "source": "cloud_posture",
                "plain": {"what": f"Cloud bucket {name} is public.", "happen": "Anyone may download business files.",
                           "do_this_week": "Block public access and rotate exposed objects.",
                           "do_this_month": "Enable account-level public-access blocks."},
            })
    for sg in snapshot.get("security_groups") or []:
        sg_name = sg.get("name") or sg.get("GroupName") or "sg"
        for rule in sg.get("inbound") or []:
            cidrs = rule.get("cidrs") or rule.get("CidrIp") or []
            if isinstance(cidrs, str): cidrs = [cidrs]
            from_port = int(rule.get("from_port") or rule.get("FromPort") or 0)
            if any(c in ("0.0.0.0/0", "::/0") for c in cidrs) and (from_port in ADMIN_PORTS or from_port == 0):
                findings.append({
                    "host": f"aws-sg:{sg_name}", "port": str(from_port),
                    "severity": "critical" if from_port in (22, 3389) else "high",
                    "title": f"Cloud firewall allows the whole internet to port {from_port} ({sg_name})",
                    "cve": "", "cma_section": "Section 3", "service": "cloud_sg",
                    "evidence": json.dumps(rule)[:800], "source": "cloud_posture",
                    "plain": {"what": f"Firewall on {sg_name} allows internet to port {from_port}.",
                               "happen": "Attackers scan and try passwords or exploits.",
                               "do_this_week": "Restrict to office/VPN addresses.",
                               "do_this_month": "Review all 0.0.0.0/0 admin rules."},
                })
    iam = snapshot.get("iam") or snapshot.get("account") or {}
    if iam.get("root_mfa") is False or iam.get("root_mfa_enabled") is False:
        findings.append({
            "host": "aws:root", "port": "cloud", "severity": "critical",
            "title": "Cloud root/owner account has no multi-factor authentication",
            "cve": "", "cma_section": "Section 3", "service": "cloud_iam",
            "evidence": json.dumps(iam)[:500], "source": "cloud_posture",
            "plain": {"what": "Master cloud account uses password only.",
                       "happen": "Leaked password can wipe the environment.",
                       "do_this_week": "Enable MFA on root today.",
                       "do_this_month": "Use daily work accounts; lock root as break-glass."},
        })
    return findings

def assess_azure(snapshot: dict) -> list[dict]:
    findings = []
    for blob in snapshot.get("storage_accounts") or []:
        name = blob.get("name") or "storage"
        if blob.get("allow_blob_public_access") or blob.get("public"):
            findings.append({
                "host": f"azure://{name}", "port": "cloud", "severity": "critical",
                "title": f"Azure storage allows public blob access: {name}",
                "cve": "", "cma_section": "Section 3", "service": "cloud_azure",
                "evidence": json.dumps(blob)[:800], "source": "cloud_posture",
            })
    for nsg in snapshot.get("nsgs") or []:
        name = nsg.get("name") or "nsg"
        for rule in nsg.get("inbound") or []:
            if rule.get("source") in ("*", "Internet", "0.0.0.0/0") and int(rule.get("port") or 0) in ADMIN_PORTS:
                findings.append({
                    "host": f"azure-nsg:{name}", "port": str(rule.get("port")), "severity": "critical",
                    "title": f"Azure NSG opens admin port {rule.get('port')} to the internet ({name})",
                    "cve": "", "cma_section": "Section 3", "service": "cloud_azure",
                    "evidence": json.dumps(rule)[:500], "source": "cloud_posture",
                })
    return findings

def run_cloud_posture(job: dict) -> list[dict]:
    snap = _load_snapshot(job)
    if not snap: return []
    provider = (job.get("cloud_provider") or snap.get("provider") or "aws").lower()
    if provider in ("azure", "az"): return assess_azure(snap)
    findings = assess_aws(snap)
    if snap.get("storage_accounts") or snap.get("nsgs"):
        findings.extend(assess_azure(snap))
    return findings
