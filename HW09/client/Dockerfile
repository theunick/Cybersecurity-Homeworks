FROM python:3.11-slim

WORKDIR /app

# Install curl and required Python packages
RUN apt-get update && \
    apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir cryptography requests

# Copy shared protocol module
COPY shared/ /app/shared/

# Copy client code
COPY client/client.py /app/

# Make the script executable
RUN chmod +x /app/client.py

# Run client
CMD ["python", "/app/client.py"]
