# C10 — Backward Compatibility Policy

1. Report files in `reports/` are never deleted by upgrades.
2. SQLite migrations are additive only.
3. API versioned: `/api/v1/` — breaking changes go to `/api/v2/` with ≥12 month notice.
4. Job JSON accepts aliases (`client` → `client_name`, `industry` → `sector`).
5. 3.x board summaries and PDFs remain valid artifacts.

MAJOR = breaking · MINOR = features · PATCH = fixes.
