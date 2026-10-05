# Full sync status (v2.4.0-p3)

## On GitHub (main)
- cyberaudit/__init__.py, config.py, security.py, db.py, workers.py
- cyberaudit/app.py (loader)
- dashboard_app.py (thin entry)
- templates/findings.html, base.html, playbooks.html, login.html, ...
- Dockerfile, docker-compose, CI, tests, pipeline client, README

## Must copy from build workspace (app body)
```bash
SRC=/home/workdir/artifacts/cyber_audit_dashboard
cp $SRC/cyberaudit/app_src_0.py $SRC/cyberaudit/app_src_1.py $SRC/cyberaudit/app_src_2.py cyberaudit/
cp $SRC/templates/index.html templates/
git add cyberaudit/app_src_*.py templates/index.html
git commit -m "Add app source chunks + overview UI" && git push
```

Without app_src_*.py the loader cannot start the Flask routes.
