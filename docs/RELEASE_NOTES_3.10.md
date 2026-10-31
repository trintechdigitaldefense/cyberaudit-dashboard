# CyberAudit 3.10 — Release Notes

**Product:** CyberAudit  
**Vendor:** TrinTech Digital Defense  
**Version:** 3.10.0  
**Date:** 2026-10-30  
**Contact:** trintechdigitaldefense@gmail.com · 1-868-362-0679 · https://trintechdigitaldefense.github.io

---

## Positioning (unchanged, non-negotiable)

- **Point-in-time** network auditing for authorised Trinidad & Tobago and Caribbean engagements.
- **Hardened and auditable** — not “impenetrable,” not “unhackable.”
- **Not** 24/7 monitoring or continuous protection.
- Computer Misuse Act (Chap. 11:17) tags are **informational engagement context**, not legal advice.
- AI-assisted wording is intended for **human review** before client delivery.

---

## Why 3.10 exists

3.10 is a **reliability and enterprise-hardening** release. It prioritises correctness, evidence integrity, and honest status over feature count.

---

## What shipped

### Phase 1 — Authorization & discovery honesty
- Signed Rules of Engagement (HMAC) with mandatory fields, expiry, and scope checks.
- Fail-closed: unsigned, expired, or out-of-scope jobs are rejected.
- Discovery does not invent live hosts from partial candidate lists.

### Phase 2 — Findings quality
- Evidence-based classification with confidence signals.
- Deduplication and false-positive suppression paths.

### Phase 3 — Intelligence package
- Complete finding enrichment: technical description, evidence, plain language, business impact, remediation priority, verification steps.
- Money/impact estimates clearly labelled as estimates with assumptions.

### Phase 4 — Report & evidence integrity
- Mandatory deliverable gate before an audit can be marked completed.
- Genuine PDF validation (magic bytes); fake PDFs excluded from packs.
- Engagement evidence pack with checksums / signed manifest where configured.

### Phase 5 — Worker & database reliability
- Atomic job claim, payload-hash deduplication, bounded retries.
- Worker heartbeats and stale-job recovery.
- Transactional finalization: job and session status stay consistent.
- Database backup and verified restore helpers.

### Phase 6 — Dashboard surfaces
- Jobs, assets, risk heatmap, remediation board, history, retest, compliance, activity, system health.
- Module health never treats **idle** as operational.

### Phase 7 — Multi-client enterprise
- Per-client isolated data roots (`data/tenants/<client_id>/`).
- Client role cannot override tenant via headers.
- Engagement lifecycle, retention (dry-run default), secure archive.
- Lab vs production environment guidance.

### Phase 8 — Regression suite
- Acceptance matrix covering ROE, packs, isolation, finalization, health honesty.
- Core Phases 1–8 suite: **59 tests passed** at release.

### Phase 9 — Documentation & Definition of Done
- This release note, DoD checklist, version bump to 3.10.0.

---

## What operators must still do

1. Set strong credentials via environment. Never ship default `admin/admin` in production.
2. Provide a signed ROE for every non-lab job.
3. Bind the dashboard to localhost or a VPN interface in production; put TLS in front for any remote access.
4. Human-review board and client wording before delivery.
5. Run retention with `dry_run=true` first; confirm archives before destructive apply.

---

## Known limitations (honest)

- Point-in-time only — no continuous monitoring claim.
- OpenVAS/GVM quality depends on a real scanner being available; otherwise that module stays idle/honest.
- Multi-tenant path switching is process-local; prefer one active tenant per worker process for strict isolation.
- Legal conclusions require a qualified human — the tool does not issue them.

---

## Repository

https://github.com/trintechdigitaldefense/cyberaudit-dashboard
