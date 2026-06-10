FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cyber_hygiene_scanner ./cyber_hygiene_scanner

ENTRYPOINT ["python", "-m", "cyber_hygiene_scanner.cli"]
