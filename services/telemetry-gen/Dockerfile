FROM python:3.11-slim

WORKDIR /app

# Standard requirements logic
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source AND data
COPY ./src /app/src
COPY ./data /app/data

# This tells the container to stay alive so we can 'exec' scripts inside it
CMD ["tail", "-f", "/dev/null"]