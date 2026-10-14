#!/usr/bin/env bash
# C5 — One-command setup
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
echo "=== CyberAudit installer ==="
command -v python3 >/dev/null || { echo "FATAL: python3 required"; exit 1; }
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
mkdir -p data reports playbooks data/inbox data/jobs data/backups
if [[ -z "${CYBERAUDIT_SECRET:-}" ]]; then
  export CYBERAUDIT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  echo "Generated CYBERAUDIT_SECRET — export it for your service:"
  echo "  export CYBERAUDIT_SECRET=$CYBERAUDIT_SECRET"
fi
export DEMO_MODE="${DEMO_MODE:-0}"
export CYBERAUDIT_HOST="${CYBERAUDIT_HOST:-127.0.0.1}"
python3 -c "from cyberaudit.db import init_db; init_db(); print('DB ready')"
echo "Run: source venv/bin/activate && python3 dashboard_app.py"
echo "Health: curl -s http://127.0.0.1:1881/health"
echo "=== done ==="
