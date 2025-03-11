FROM python:3.10-slim
WORKDIR /app
RUN mkdir -p /data /certs
COPY DarkGate/proxy/requirements.txt ./DarkGate/proxy/requirements.txt
RUN pip install --no-cache-dir -r DarkGate/proxy/requirements.txt
COPY . .
CMD ["python", "-m", "DarkGate.proxy.app"]
