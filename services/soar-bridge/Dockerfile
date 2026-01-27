FROM python:3.11-slim

WORKDIR /app

# Dependency management
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Service source
COPY ./src /app/src
COPY ./config /app/config

# 🚨 CRITICAL: Ensure the bridge sees /app/shared for Privacy and Intel modules
ENV PYTHONPATH="/app/src:/app/shared"
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Execute the dispatcher with unbuffered logs
CMD ["python", "-u", "src/main.py"]