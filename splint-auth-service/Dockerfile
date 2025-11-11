# Use a lightweight, official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy all your files into the container
COPY . .

# Install system dependencies first (for psycopg2 and other libs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    requests \
    psycopg2-binary \
    python-dotenv \
    python-jose \
    passlib \
    eventlet \
    flask \
    flask-socketio

# Expose the port your app runs on
EXPOSE 5000

# Command to start your app
CMD ["python", "admin_panel.py"]
