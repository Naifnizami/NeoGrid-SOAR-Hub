# Standard enterprise lightweight base
FROM python:3.11-slim

# The 'Home' of our service inside the container
WORKDIR /app

# Step 1: Install dependencies first (better build speed)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Step 2: Copy the source code
COPY ./src /app/src

# Step 3: Copy the config folder (CRITICAL: Logic relies on soar_config.yaml)
COPY ./config /app/config

# Note: The /shared folder will NOT be copied. 
# It will be "Mounted" live via the docker-compose file.

# Listen on Port 8000
EXPOSE 8000

# Execute the dispatcher
CMD ["python", "src/main.py"]