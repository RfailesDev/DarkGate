# DarkGate/admin/Dockerfile
FROM python:3.10-slim

WORKDIR /app

# Создаем каталоги для данных и сертификатов
RUN mkdir -p /data /certs

# Копируем и устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь исходный код
COPY . .

# Запускаем приложение с Gunicorn на порту 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
