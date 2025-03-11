FROM python:3.10-slim
WORKDIR /app

# Создаем директории заранее
RUN mkdir -p /data /certs

# Копируем requirements.txt.  Путь относительный.
COPY requirements.txt ./

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь код админки
COPY . .

# Запускаем приложение
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "4"]