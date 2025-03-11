FROM python:3.10-slim
WORKDIR /app

# Создаем директории заранее
RUN mkdir -p /data /certs

# Копируем requirements.txt
COPY requirements.txt ./

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь код прокси
COPY . .

# Запускаем приложение
CMD ["python", "app.py"]