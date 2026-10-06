FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEMO_MODE=0 \
    CYBERAUDIT_HOST=0.0.0.0 \
    CYBERAUDIT_PORT=1881

RUN apt-get update && apt-get install -y --no-install-recommends nmap iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data reports data/inbox/processed data/inbox/failed data/jobs playbooks

EXPOSE 1881

CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "-b", "0.0.0.0:1881", "--timeout", "300", "dashboard_app:app"]
