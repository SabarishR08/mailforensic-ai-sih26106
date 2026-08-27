FROM python:3.11-slim

# System deps for geoip2, opencv, pyzbar
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev \
    libgl1-mesa-glx libglib2.0-0 \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY backend/ backend/
COPY dashboard/ dashboard/
COPY training/ training/
COPY data/ data/
COPY .env.example .env.example

# Create dirs
RUN mkdir -p uploads/reports backend/credentials backend/logs

# Default env
ENV FLASK_SECRET_KEY=change-me-in-production
ENV DEBUG_MODE=false
ENV PORT=5000

EXPOSE 5000

COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

ENTRYPOINT ["./docker-entrypoint.sh"]
