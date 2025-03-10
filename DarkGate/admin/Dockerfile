# DarkGate/DarkGate/admin/Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Команда для запуска (для продакшена, с Gunicorn и Uvicorn)
CMD ["gunicorn", "--workers=4", "--bind=0.0.0.0:5000", "--worker-class=uvicorn.workers.UvicornWorker", "DarkGate.admin.app:app"]