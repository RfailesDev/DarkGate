# Используем корневой контекст проекта
FROM python:3.10-slim
WORKDIR /app
RUN mkdir -p /data /certs
COPY DarkGate/requirements.txt ./DarkGate/admin/requirements.txt
RUN pip install --no-cache-dir -r DarkGate/admin/requirements.txt
COPY . .
CMD ["gunicorn", "-b", "0.0.0.0:5000", "DarkGate.admin.app:app"]
