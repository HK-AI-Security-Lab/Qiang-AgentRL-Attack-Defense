FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    curl \
    util-linux \
    procps \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -u 1000 -m -s /bin/bash app

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN mkdir -p /etc/autopatch && chown -R app:app /app /etc/autopatch

EXPOSE 8080

CMD ["python", "/app/app.py"]
