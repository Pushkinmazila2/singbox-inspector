FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY run.py rule_checker.py leak_checker.py exporter.py .

ENTRYPOINT ["python3", "/app/run.py"]
