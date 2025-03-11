FROM python:3.11-slim

WORKDIR /app

# Копируем файл зависимостей из текущей директории
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь исходный код
COPY . /app

# Запускаем приложение
CMD ["python", "app.py"]
