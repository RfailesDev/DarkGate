FROM python:3.11-slim

# Устанавливаем рабочую директорию в контейнере (корень проекта)
WORKDIR /app

# Копируем весь проект в контейнер
COPY . /app

# Устанавливаем зависимости для админ-панели
RUN pip install --no-cache-dir -r DarkGate/admin/requirements.txt

# Запускаем админ-панель как модуль, что обеспечивает корректное разрешение относительных импортов
CMD ["python", "-m", "DarkGate.admin.app"]
