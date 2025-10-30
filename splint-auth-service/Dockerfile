# Use a general Debian base image to ensure a single, stable Python environment
FROM debian:bookworm-slim

# Set the working directory in the container
WORKDIR /app

# Install Python and all required libraries using the system's package manager
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-fastapi \
    python3-uvicorn \
    python3-jwt \
    python3-passlib \
    python3-multipart \
    && rm -rf /var/lib/apt/lists/*

# --- CRITICAL FIX: Copy files from within this service's directory ---
# This is now simple and reliable because users.json is in the same folder.
COPY ./users.json /app/users.json
COPY ./auth_service.py /app/

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application
CMD ["python3", "-m", "uvicorn", "auth_service:app", "--host", "0.0.0.0", "--port", "8000", "--ssl-keyfile", "./key.pem", "--ssl-certfile", "./cert.pem"]

