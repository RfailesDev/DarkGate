FROM python:3.11-slim

WORKDIR /app

COPY proxy/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common /app/common
COPY proxy /app/proxy

RUN mkdir -p /certs /data

EXPOSE 80 443 8899

CMD ["python", "proxy/app.py"]