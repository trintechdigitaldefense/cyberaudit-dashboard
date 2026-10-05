# Sync remaining modular files (v2.4.0-p3)

These files are complete in the build workspace and need a final `git push` from a machine that has them:

```
/home/workdir/artifacts/cyber_audit_dashboard/
  dashboard_app.py          # thin entry (imports cyberaudit.*)
  cyberaudit/db.py
  cyberaudit/workers.py
  templates/findings.html
  templates/base.html       # Findings nav link
  templates/playbooks.html  # Trigger button
  templates/index.html      # Start audit form
```

```bash
SRC=/home/workdir/artifacts/cyber_audit_dashboard
cp $SRC/dashboard_app.py .
cp $SRC/cyberaudit/db.py cyberaudit/
cp $SRC/cyberaudit/workers.py cyberaudit/
cp $SRC/templates/findings.html templates/
cp $SRC/templates/base.html templates/
cp $SRC/templates/playbooks.html templates/
cp $SRC/templates/index.html templates/
git add -A && git commit -m "Complete P3 modular app + findings UI" && git push
```

Already on GitHub: `cyberaudit/__init__.py`, `config.py`, `security.py`, Dockerfile, CI, tests, pipeline client, README.
