FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DEMO_MODE=0 CYBERAUDIT_HOST=0.0.0.0 CYBERAUDIT_PORT=1881
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY dashboard_app.py .
COPY cyberaudit/ cyberaudit/
COPY templates/ templates/
COPY playbooks/ playbooks/
RUN mkdir -p data reports data/inbox/processed data/inbox/failed data/jobs
EXPOSE 1881
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "-b", "0.0.0.0:1881", "--timeout", "120", "dashboard_app:app"]
