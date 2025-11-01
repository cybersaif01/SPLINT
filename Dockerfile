FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for psycopg2 and others
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd --create-home app
USER app

# Copy project files
COPY --chown=app:app . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir gunicorn

# 🔧 Add this line so the PATH includes where pip installs executables
ENV PATH="/home/app/.local/bin:${PATH}"


# Expose port
EXPOSE 5000

# Run the app with Gunicorn
CMD ["gunicorn", "--certfile=./cert.pem", "--keyfile=./key.pem", "--bind", "0.0.0.0:5000", "server.admin_panel:app"]
