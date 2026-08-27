#!/bin/bash
set -e

echo "========================================"
echo "  AI Email Forensics Platform"
echo "========================================"

# Check for trained models
MODEL_DIR="backend/ml_models"
MISSING=""
for f in email_model.pkl email_vectorizer.pkl url_model.pkl url_vectorizer.pkl; do
    if [ ! -f "$MODEL_DIR/$f" ]; then
        MISSING="$MISSING $f"
    fi
done

if [ -n "$MISSING" ]; then
    echo ""
    echo "WARNING: Missing model files:$MISSING"
    echo ""
    echo "Models not found in $MODEL_DIR/. The platform will start but"
    echo "ML predictions will return 'unknown'."
    echo ""
    echo "To train models:"
    echo "  1. Run training/train.py on Google Colab"
    echo "  2. Copy .pkl files to $MODEL_DIR/"
    echo "  3. Rebuild: docker compose up --build"
    echo ""
fi

# Check for GeoLite2 database
if [ ! -f "data/GeoLite2-City.mmdb" ]; then
    echo "INFO: GeoLite2-City.mmdb not found in data/"
    echo "      Geo service will fall back to ipapi.co (1000 req/day)."
    echo "      Download free from: https://www.maxmind.com/en/geolite2/signup"
    echo ""
fi

# Check for Gmail credentials
if [ ! -f "backend/credentials/credentials.json" ]; then
    echo "INFO: Gmail credentials not found."
    echo "      Gmail scanning will be unavailable."
    echo "      Set up OAuth at: https://console.cloud.google.com/apis/credentials"
    echo ""
fi

echo "Starting platform on port ${PORT:-5000}..."
echo "Dashboard: http://localhost:${PORT:-5000}/dashboard"
echo ""

exec python -m backend.app
