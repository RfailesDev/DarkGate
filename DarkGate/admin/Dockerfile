# admin/Dockerfile

FROM python:3.11-slim

WORKDIR /app

COPY ./admin/requirements.txt /app/admin/
COPY ./common /app/common
COPY ./admin /app/admin

RUN pip install --no-cache-dir -r /app/admin/requirements.txt

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "admin.app:app"]