FROM python:3.11-slim

WORKDIR /app/admin

# Копируем файл зависимостей из текущей директории
COPY requirements.txt /app/admin/
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь исходный код
COPY . /app/admin

CMD ["python", "app.py"]
