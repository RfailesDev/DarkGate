# proxy/Dockerfile

FROM python:3.11-slim

WORKDIR /app

COPY ./proxy/requirements.txt /app/proxy/
COPY ./common /app/common
COPY ./proxy /app/proxy

RUN pip install --no-cache-dir -r /app/proxy/requirements.txt

# No EXPOSE needed here, as the ports are exposed by docker-compose
# and handled by the proxy server itself

CMD ["python", "proxy/app.py"]