# DarkGate/admin/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Сначала копируем только файл с зависимостями, чтобы использовать кэширование
COPY DarkGate/admin/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Потом копируем все остальные файлы приложения
COPY DarkGate/admin ./admin
COPY DarkGate/common ./common

# Установка PYTHONPATH
ENV PYTHONPATH=/app:$PYTHONPATH

# Запуск через gunicorn (более production-ready)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "admin.app:app"]