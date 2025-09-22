FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

# Entrypoint
# Use `fastmcp run` if you use CLI runner OR call python directly if you use `app.run()`
# Here we assume you call app.run() inside main.py
CMD ["python3", "cortex-mcp.py"]
