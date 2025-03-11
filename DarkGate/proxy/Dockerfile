# DarkGate/proxy/Dockerfile
FROM python:3.11-slim
WORKDIR /app

COPY ./DarkGate/proxy/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./DarkGate /app/DarkGate

CMD ["python", "-m", "DarkGate.proxy.app"]