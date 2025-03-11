# DarkGate/proxy/Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Добавляем /app в PYTHONPATH
ENV PYTHONPATH=/app:$PYTHONPATH

CMD ["python", "proxy/app.py"]