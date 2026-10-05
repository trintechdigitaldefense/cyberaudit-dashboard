# Canonical dashboard_app.py

The full **v2.3.0-p2** application lives in the working tree used to develop this repo.

**Local path (source of truth until this file is replaced on GitHub):**

`/home/workdir/artifacts/cyber_audit_dashboard/dashboard_app.py`

To publish from a machine with this checkout:

```bash
cp /home/workdir/artifacts/cyber_audit_dashboard/dashboard_app.py .
cp /home/workdir/artifacts/cyber_audit_dashboard/templates/index.html templates/
git add dashboard_app.py templates/index.html
git commit -m "Sync P0-P2 dashboard_app and overview UI"
git push origin main
```

Features in that file: P0 security, P1 ingest/inbox/retention, P2 ack/jobs/findings/RBAC.
