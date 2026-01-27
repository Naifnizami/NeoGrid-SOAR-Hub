# Use a lightweight but stable Python base
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# 1. Dependency Management
# We copy only requirements first to leverage Docker's cache layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. Source Code & Tools
# Explicitly copying the structured folders
COPY ./src /app/src
COPY ./tools /app/tools

# 🚨 ENTERPRISE ENV SETTINGS:
# PYTHONPATH ensures that 'import tools' works. 
# We add /app/shared so the Agent can access shared intelligence (mitre_db.json, privacy_engine.py).
ENV PYTHONPATH="/app:/app/shared"

# Python Unbuffered allows logs to flow immediately to docker-compose output
ENV PYTHONUNBUFFERED=1

# Expose internal Service Port
EXPOSE 8001

# Command to launch the service
# We use -u for unbuffered logs to help with real-time SOC monitoring
CMD ["python", "-u", "src/main.py"]