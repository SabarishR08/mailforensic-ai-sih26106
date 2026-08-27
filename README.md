# AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

> SIH26106 — Smart India Hackathon 2026

## Architecture

```
ai-email-forensics/
├── backend/
│   ├── ml_pipeline/        # ML models (stacking ensemble)
│   │   ├── data_loader.py  # Kaggle dataset loading
│   │   ├── feature_engineering.py  # TF-IDF + 29 manual features
│   │   ├── model_builder.py  # LR + RF + XGB + LGBM stacking
│   │   ├── evaluator.py    # Metrics & confusion matrix
│   │   └── pipeline.py     # End-to-end orchestrator
│   ├── services/
│   │   ├── ml_predictor.py      # ML prediction service
│   │   ├── geo_service.py       # MaxMind GeoLite2 + ipapi
│   │   ├── forensic_analyzer.py # Header forensics + routing chain
│   │   ├── forensic_report.py   # PDF report (ReportLab)
│   │   ├── threat_intelligence.py  # VT + SafeBrowsing + RDAP
│   │   ├── risk_scoring.py      # Unified 0-100 scoring
│   │   ├── gemini_service.py    # AI enrichment
│   │   ├── gmail_service.py     # Gmail API
│   │   └── email_scanner.py     # Orchestrates full pipeline
│   ├── routes/              # Flask blueprints
│   └── app.py              # Entry point
├── dashboard/               # Flask templates (Leaflet.js maps)
├── training/
│   ├── train.py            # Training script (run on Colab)
│   ├── colab_setup.py      # Colab environment setup
│   └── colab_notebook_cells.py  # Copy-paste Colab cells
└── data/                   # Kaggle datasets (gitignored)
```

## Quick Start

### 1. Train Models (Google Colab)

1. Upload `Kaggle_datasets.zip` to Colab
2. Clone this repo or upload it
3. Run:
   ```bash
   !pip install -q scikit-learn xgboost lightgbm pandas numpy scipy
   !unzip -q Kaggle_datasets.zip -d data/
   !python training/train.py --model both --data-dir data --model-dir backend/ml_models
   ```
4. Download the `.pkl` files from `backend/ml_models/`

### 2. Run Platform (Local)

```bash
# Install dependencies
pip install -r requirements.txt

# Copy trained models into backend/ml_models/
# Place GeoLite2-City.mmdb in data/ (free from MaxMind)
# Copy .env.example to .env and add your API keys

# Run
python -m backend.app
```

Dashboard: http://localhost:5000/dashboard

### 3. Run Platform (Docker)

```bash
# Copy trained models into backend/ml_models/
# Copy .env.example to .env and add your API keys

# One command to build and run
docker compose up --build

# Or run in background
docker compose up -d --build
```

The entrypoint checks for models, GeoLite2, and Gmail credentials on startup and warns if anything is missing.

**Volumes mounted:**
- `backend/ml_models/` → trained .pkl models
- `data/` → GeoLite2-City.mmdb
- `backend/credentials/` → Gmail OAuth
- `uploads/` → generated reports
- `instance/` → SQLite database

Dashboard: http://localhost:5000/dashboard

### 4. Features

- **ML Detection**: Stacking ensemble (LR+RF+XGBoost+LightGBM) with 15k+ TF-IDF features + 29 manual features
- **GeoLocation**: IP → City/Country/ASN with country risk tiers and hosting provider detection
- **Forensic Intelligence**: SPF/DKIM/DMARC analysis, Received chain tracing with per-hop geo, header mismatch detection
- **Risk Scoring**: Weighted composite of ML, threat intel, authentication, geolocation, and forensic signals (0-100)
- **PDF Reports**: Downloadable forensic breakdowns per email
- **Threat Map**: Leaflet.js visualization of threat origins
- **Gmail Integration**: Live scan of inbox with full pipeline analysis
- **Gemini AI**: NLP classification and threat fusion enrichment

## Team: Mutex

| Member | Track |
|--------|-------|
| [You] | ML Integration + Architecture |
| Vignesh | GeoLocation |
| Shafeeq | Forensic Intelligence |
| Rohith | Dashboard + Demo |

## Dataset Sources

- Email Phishing Legitimate Classifier (Kaggle)
- Spam Email Dataset (Kaggle)
- Human-LLM Generated Phishing Emails (Kaggle)
- Binary Phishing/Legitimate URLs (Kaggle)
- Legitimate/Phishing Website Dataset (Kaggle)
