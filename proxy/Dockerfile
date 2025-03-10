FROM python:3.11-slim

WORKDIR /app

# Копируем requirements.txt *внутри* папки proxy
COPY proxy/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем common и proxy
COPY common /app/common
COPY proxy /app/proxy

# Эти COPY *.py  и  mkdir -p /certs /data  нужно делать ПОСЛЕ копирования папок,
#  иначе они могут быть перезаписаны
RUN mkdir -p /certs /data

EXPOSE 80 443 8899

CMD ["python", "app.py"]