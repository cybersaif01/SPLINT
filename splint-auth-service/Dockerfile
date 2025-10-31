# Use a general Debian base image to ensure a single, stable Python environment
FROM debian:bookworm-slim

# Set the working directory in the container
WORKDIR /app

# Install Python and all required libraries using the system's package manager
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && pip install fastapi uvicorn python-jose python-multipart python-dotenv \
    && rm -rf /var/lib/apt/lists/*

# Copy the app files
COPY ./users.json /app/users.json
COPY ./auth_service.py /app/

# Expose the port the app runs on
EXPOSE 8000

# Command to run the FastAPI app
CMD ["uvicorn", "auth_service:app", "--host", "0.0.0.0", "--port", "8000"]
