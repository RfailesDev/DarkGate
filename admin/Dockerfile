FROM python:3.11-slim

WORKDIR /app

COPY admin/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common /app/common
COPY admin /app/admin

RUN mkdir -p /data /certs

EXPOSE 5000

ENV FLASK_APP=app.py
ENV FLASK_ENV=production

CMD ["python", "admin/app.py"]