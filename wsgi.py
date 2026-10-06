"""Production WSGI entry (gunicorn)."""
from cyberaudit.app import app, socketio, ensure_workers

ensure_workers()

application = app
