FROM python:3.11-slim

WORKDIR /app

# 1. Dependency Management
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. Source & Simulation Data
COPY ./src /app/src
COPY ./data /app/data

# 3. Environment Tuning
# Ensure EDR agent logs appear immediately for demo purposes
ENV PYTHONUNBUFFERED=1
# Make sure src is in path so scripts can find each other
ENV PYTHONPATH="/app"

# Expose Port 5000 (The Mock Containment/EDR Listener)
EXPOSE 5000

# 4. Entrypoint
# We start the listener.py (The EDR Agent) by default.
# This ensures that when you run 'docker-compose up', the containment endpoint is LIVE.
CMD ["python", "src/listener.py"]