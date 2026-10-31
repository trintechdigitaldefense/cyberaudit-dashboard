# CyberAudit 3.10.3

Core integration completion. Point-in-time authorized audits — not continuous monitoring.

## Verified locally

- Tenant isolation via `tenant_scope` + `get_db()` without assigning `config.DB_PATH`.
- Static `pipeline_helpers` (no `exec` of body text in authorized path).
- Job claim exclusive.
- Unsigned manifests not verified when signing secret is set.
- Version string **3.10.3**.

## Limitations

- Prefer one tenant per worker process.
- Green GitHub Actions must be confirmed on the release SHA — local pytest is not a substitute.
