FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r DarkGate/admin/requirements.txt \
    && rm -rf DarkGate/proxy/

# Указываем команду для запуска приложения с Gunicorn и Uvicorn workers
CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "DarkGate.admin.app:app", "-b", "0.0.0.0:5000"]