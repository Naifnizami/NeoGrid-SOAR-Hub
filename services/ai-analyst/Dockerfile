# Use an industry-standard lightweight Python image
FROM python:3.11-slim

# Create the work directory inside the container
WORKDIR /app

# Copy the requirements file from the current folder
# (Make sure you have a requirements.txt in the ai-analyst folder)
COPY requirements.txt .

# Install the necessary libraries (fastapi, agno, requests, etc.)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the internal service structure
# We copy them specifically so the container mirrors our local organization
COPY ./src /app/src
COPY ./tools /app/tools

# 🚨 CRITICAL: The PYTHONPATH variable allows the script in /app/src/ 
# to import from the folder /app/tools/ as a peer.
ENV PYTHONPATH=/app

# Expose the internal Port we've been using for the Analyst
EXPOSE 8001

# Command to launch the Analyst service
CMD ["python", "src/main.py"]