#!/bin/bash
set -e

echo "========================================"
echo "  AI Email Forensics Platform"
echo "========================================"

# Check for trained models
MODEL_DIR="backend/ml/models"
MISSING=""
for f in xgb_email_threat_model.pkl lgb_email_threat_model.pkl tfidf_vectorizer.pkl feature_cols.json; do
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
    echo "  1. Open Colab notebook from README link"
    echo "  2. Run training -> download .pkl files"
    echo "  3. Copy to $MODEL_DIR/"
    echo "  4. Rebuild: docker compose up --build"
    echo ""
fi

# Check for BERT model (optional — XGB+LGB work without it)
if [ -f "$MODEL_DIR/distilbert_email_threat/config.json" ]; then
    echo "✅ DistilBERT model found — full ensemble enabled"
else
    echo "ℹ️  DistilBERT not found — running XGB+LGB ensemble only (97.5% acc)"
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
