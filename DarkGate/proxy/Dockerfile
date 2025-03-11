# DarkGate/proxy/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Сначала копируем только файл с зависимостями, чтобы использовать кэширование
COPY DarkGate/proxy/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Потом копируем все остальные файлы приложения
COPY DarkGate/proxy ./proxy
COPY DarkGate/common ./common
COPY DarkGate/__init__.py ./__init__.py

# Установка PYTHONPATH
ENV PYTHONPATH=/app:$PYTHONPATH

CMD ["python", "proxy/app.py"]