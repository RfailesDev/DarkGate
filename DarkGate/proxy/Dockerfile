# DarkGate/proxy/Dockerfile
FROM python:3.10-slim

WORKDIR /app

# Создаем каталоги для данных и сертификатов
RUN mkdir -p /data /certs

# Копируем и устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь исходный код
COPY . .

# Запускаем приложение
CMD ["python", "app.py"]
