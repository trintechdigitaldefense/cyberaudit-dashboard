"""P6.2 — Credential leak check against operator-supplied breach corpus."""
from __future__ import annotations
import json, logging, os, re
from pathlib import Path
from cyberaudit import config
logger = logging.getLogger("CyberAuditDashboard")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

def _corpus_path() -> Path:
    env = os.environ.get("CYBERAUDIT_BREACH_CORPUS", "").strip()
    return Path(env) if env else config.DATA_DIR / "breach_corpus.jsonl"

def load_corpus(path: Path | None = None) -> list[dict]:
    path = path or _corpus_path()
    if not path.is_file(): return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line: continue
        try: rows.append(json.loads(line))
        except json.JSONDecodeError:
            if "@" in line: rows.append({"email": line.lower().strip(), "source": "corpus", "year": ""})
    return rows

def check_emails(emails: list[str], corpus: list[dict] | None = None) -> list[dict]:
    corpus = corpus if corpus is not None else load_corpus()
    index: dict[str, list] = {}
    for row in corpus:
        em = (row.get("email") or "").lower().strip()
        if em: index.setdefault(em, []).append(row)
    findings = []
    for email in emails:
        email = email.lower().strip()
        hits = index.get(email) or []
        if not hits: continue
        sources = sorted({str(h.get("source") or "known breach") for h in hits})
        findings.append({
            "host": email.split("@")[-1], "port": "", "severity": "high",
            "title": f"Credential exposure: {email}", "cve": "", "cma_section": "Section 6",
            "service": "credential_leak", "evidence": f"Matched corpus sources: {', '.join(sources)}",
            "source": "credential_leak", "email": email, "breach_sources": sources,
            "plain": {
                "what": f"The address {email} appears in a known breach dataset loaded for this engagement.",
                "happen": "Attackers try those passwords on email, banking, and cloud logins.",
                "do_this_week": "Force a password reset for this account and enable multi-factor authentication.",
                "do_this_month": "Check password reuse on other company systems; staff reminder on unique passwords.",
            },
        })
    return findings

def check_domain(domain: str, corpus: list[dict] | None = None) -> list[dict]:
    domain = (domain or "").lower().strip().lstrip("@")
    if not domain: return []
    corpus = corpus if corpus is not None else load_corpus()
    emails = [ (row.get("email") or "").lower() for row in corpus if (row.get("email") or "").lower().endswith("@" + domain) ]
    return check_emails(sorted(set(emails)), corpus)

def run_credential_check(job: dict) -> list[dict]:
    corpus = load_corpus(Path(job["breach_corpus_file"])) if job.get("breach_corpus_file") else None
    findings = []
    if job.get("domain") or job.get("email_domain"):
        findings.extend(check_domain((job.get("domain") or job.get("email_domain") or "").strip(), corpus))
    emails = job.get("emails") or []
    if isinstance(emails, str): emails = [m.group(0).lower() for m in _EMAIL_RE.finditer(emails)]
    if emails: findings.extend(check_emails(list(emails), corpus))
    seen, out = set(), []
    for f in findings:
        if f.get("email") in seen: continue
        seen.add(f.get("email")); out.append(f)
    return out
