FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
# Render sends traffic to $PORT (10000 by default).
# 1. Create the schema and the demo accounts (does nothing if they already exist).
# 2. Start the app. main.py exposes a factory, create_app(), not a module-level "app".
#    One worker on purpose: rate limiting and the audit anchor writer are in-process.
CMD ["sh", "-c", "python scripts/init_db.py --seed && exec uvicorn trustvault.main:create_app --factory --host 0.0.0.0 --port ${PORT:-10000} --workers 1"]
