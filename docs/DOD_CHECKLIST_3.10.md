# CyberAudit 3.10 — Definition of Done Checklist

Use this before calling a build **client-ready**. Every item must be true or explicitly waived in writing by the engagement lead.

---

## A. Authorization & scope

- [ ] Signed ROE required for non-lab jobs
- [ ] Unsigned ROE rejected
- [ ] Expired ROE rejected
- [ ] Out-of-scope target rejected
- [ ] In-scope target accepted under valid ROE
- [ ] ROE client identity matches engagement client when multi-client is used

## B. Discovery & findings

- [ ] Unresponsive hosts are not reported as live
- [ ] Findings carry severity and evidence or explicit confidence limits
- [ ] False-positive / suppression path is reviewable
- [ ] Director / plain-language fields do not invent legal conclusions

## C. Completion & evidence

- [ ] Audit cannot be marked **completed** without mandatory deliverables
- [ ] Executive / client text present when completion claimed
- [ ] Technical annex present when completion claimed
- [ ] PDF artefacts pass magic-byte validation (or are omitted, not faked)
- [ ] Engagement pack ZIP opens and is integrity-clean when produced
- [ ] Failed audits are marked **failed**, not completed

## D. Jobs & database

- [ ] Job claim is exclusive (second worker cannot steal a live claim)
- [ ] Stale running jobs can be recovered or failed after heartbeat timeout
- [ ] Partial report cleanup runs on failure
- [ ] Database backup produces a readable SQLite file
- [ ] Job and session status stay aligned after finalization

## E. Multi-client

- [ ] Tenant data roots are separate (db / reports / jobs)
- [ ] Client role cannot switch tenant via `X-CyberAudit-Tenant`
- [ ] Retention dry-run does not delete files

## F. Dashboard honesty

- [ ] Idle modules labelled idle / not executed — not “healthy monitoring”
- [ ] No dead nav items for shipped surfaces
- [ ] CMA view includes “not legal advice” disclaimer
- [ ] Point-in-time language visible on overview / about

## G. Security baseline

- [ ] No default `admin` / `admin` in production configuration
- [ ] `CYBERAUDIT_SECRET` set to a long random value
- [ ] `AUTH_REQUIRED` on in production
- [ ] Dashboard not bound to `0.0.0.0` without TLS + network controls
- [ ] CSRF / session hardening enabled on state-changing routes

## H. Tests & release

- [ ] `pytest tests/test_phase8_regression.py` passes
- [ ] Core suite Phases 1–8 passes on fresh data dir
- [ ] CHANGELOG.md lists 3.10 phases
- [ ] RELEASE_NOTES_3.10.md matches shipped behaviour (no vapour features)
- [ ] Version string is **3.10.0** in config / about

## I. Engagement delivery

- [ ] Human reviewed board summary before send
- [ ] Currency consistent (TT$ with optional US$ equivalent — not mixed casually)
- [ ] ROE and scope archived with the engagement pack
- [ ] Client told explicitly this was a point-in-time audit

---

**Sign-off**

| Role | Name | Date | Result |
|------|------|------|--------|
| Operator | | | Pass / Fail |
| Reviewer | | | Pass / Fail |
| Founder / Lead | | | Pass / Fail |

Waivers (if any): _______________________________________________
