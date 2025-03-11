FROM python:3.11-slim

# Устанавливаем рабочую директорию в контейнере (корень проекта)
WORKDIR /app

# Копируем весь проект в контейнер
COPY . /app

# Устанавливаем зависимости для прокси-сервера
RUN pip install --no-cache-dir -r DarkGate/proxy/requirements.txt

# Запускаем прокси-сервер как модуль, что обеспечивает корректное разрешение относительных импортов
CMD ["python", "-m", "DarkGate.proxy.app"]
