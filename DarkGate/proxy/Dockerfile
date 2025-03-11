FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r DarkGate/proxy/requirements.txt \
    && rm -rf DarkGate/admin/ \
    && rm -rf test_server/

CMD ["python", "DarkGate/proxy/app.py"]