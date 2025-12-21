FROM python:3.11-slim

WORKDIR /app

# Install required packages
RUN pip install --no-cache-dir cryptography requests

# Copy shared protocol module
COPY shared/ /app/shared/

# Copy server code
COPY server/server.py /app/

# Make the script executable
RUN chmod +x /app/server.py

# Expose VPN port
EXPOSE 8443

# Run server
CMD ["python", "/app/server.py"]
