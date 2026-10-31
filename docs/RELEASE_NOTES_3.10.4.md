# CyberAudit 3.10.4

Sync release consolidating 3.10.3 core integration on the default branch.

- Point-in-time authorized audits only — not continuous monitoring.
- Tenant DB paths via `resolve_db_path()` / `tenant_scope`.
- ROE-first `pipeline_authorized.run_audit_job`.
- Static `pipeline_helpers` (no runtime body exec).
- Worker claim + transactional finalize.
- Unsigned packs not verified when signing secret is set.

Confirm GitHub Actions on this SHA before production use.
