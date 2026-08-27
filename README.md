# 🛡️ AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

> **SIH26106** — Smart India Hackathon 2026 | AICTE Problem Statement

---

## 🔗 Quick Links (START HERE)

| Resource | Link |
|----------|------|
| **📂 Training Datasets (Google Drive)** | [Open Drive Folder](https://drive.google.com/drive/folders/1MqyAdNHZFGVQzfDx5VwszbqbiEgm-Wg0?usp=drive_link) |
| **📓 Colab Training Notebook** | [Open in Colab](https://colab.research.google.com/drive/1Rqz3TkPnmXebt8jz39oWvjM6Q-P4J-T1?usp=sharing) |
| **📦 GitHub Repository** | [github.com/SabarishR08/sih26106](https://github.com/SabarishR08/sih26106) |

> ⚡ **The Colab notebook trains 3 models: XGBoost → LightGBM → DistilBERT.**
> All datasets are pre-uploaded to Google Drive — just open the notebook and click **Runtime → Run all**.

---

## 📊 Architecture

```
ai-email-forensics/
├── backend/
│   ├── ml/                 # Trained models + inference
│   │   ├── models/             # .pkl files + DistilBERT weights
│   │   │   ├── xgb_email_threat_model.pkl   (963 KB)
│   │   │   ├── lgb_email_threat_model.pkl   (3.2 MB)
│   │   │   ├── tfidf_vectorizer.pkl         (1.2 MB)
│   │   │   ├── feature_cols.json
│   │   │   ├── model_comparison.json
│   │   │   └── distilbert_email_threat/      (268 MB, optional)
│   │   └── email_classifier.py  # Standalone inference module
│   ├── ml_pipeline/        # Training pipeline code (reference)
│   ├── services/
│   │   ├── ml_predictor.py      # ML prediction (XGB+LGB, auto-detects BERT)
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
│   ├── SIH26106_Email_Threat_Detection_Training.ipynb  ← THE notebook
│   └── datasets/            # Local copy of training data (also in Drive)
├── tests/                   # 95 unit tests
├── Dockerfile               # Container deployment
└── docker-compose.yml       # One-command launch
```

---

## 🚀 Quick Start

### Step 1 — Train Models (Google Colab)

1. **Open the notebook**: [Click here to open in Colab](https://colab.research.google.com/drive/1Rqz3TkPnmXebt8jz39oWvjM6Q-P4J-T1?usp=sharing)
2. **Enable GPU**: Runtime → Change runtime type → T4 GPU
3. **Run all cells**: Runtime → Run all (or Ctrl+F9)
4. **Wait** ~45-90 min (XGBoost + LightGBM are fast, DistilBERT takes time)
5. **Models save to Google Drive** at `MyDrive/trained_models/`

### Step 2 — Run Platform (Local)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy trained models from Google Drive
#    Download from MyDrive/trained_models/ → place in backend/ml/models/

# 3. (Optional) Place GeoLite2-City.mmdb in data/
#    Free from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

# 4. Copy .env.example to .env and add your API keys

# 5. Run
python -m backend.app
```

Dashboard: http://localhost:5000/dashboard

### Step 3 — Run Platform (Docker)

```bash
docker compose up --build
```

---

## ✨ Features

| Feature | Status | Description |
|---------|--------|-------------|
| ML Detection | ✅ | XGBoost + LightGBM ensemble (97.5% acc) + optional DistilBERT (98.9% acc) |
| GeoLocation | ✅ | IP → City/Country/ASN with MaxMind GeoLite2 + ipapi fallback, country risk tiers |
| Forensic Intelligence | ✅ | SPF/DKIM/DMARC analysis, Received chain tracing, per-hop geo, header mismatches |
| Risk Scoring | ✅ | Weighted composite: ML + intel + auth + geo + forensic + content (0-100) |
| PDF Reports | ✅ | Downloadable forensic breakdowns per email |
| Threat Map | ✅ | Leaflet.js visualization of threat origins |
| Live Demo Mode | ✅ | Real-time SocketIO email analysis dashboard |
| Forensic .eml | ✅ | Upload .eml files for analysis without Gmail credentials |
| Threat Intel Dashboard | ✅ | Phishing trends, auth failure rates, country heatmap |
| Gmail Integration | ✅ | Live scan of inbox with full pipeline analysis |
| Unit Tests | ✅ | 95 passing tests (ML pipeline + forensics + services) |

### Model Accuracy (from Colab training)

| Model | Accuracy | F1 | AUC | Disk Size | RAM |
|-------|----------|-----|-----|-----------|-----|
| XGBoost | 97.4% | 96.2% | 99.6% | 963 KB | ~50 MB |
| LightGBM | 97.6% | 96.4% | 99.6% | 3.2 MB | ~30 MB |
| DistilBERT | 98.9% | 98.4% | 99.9% | 268 MB | ~500 MB |
| **XGB+LGB Ensemble** | **97.5%** | **96.4%** | **99.6%** | **4.2 MB** | **~80 MB** |
| **Full 3-Model Ensemble** | **98.9%** | **98.4%** | **99.9%** | **272 MB** | **~600 MB** |

> 💡 **Deployment tip**: The XGB+LGB ensemble fits on any free tier (Render, Railway, etc.).
> The DistilBERT model adds 99% accuracy but requires ~2GB RAM — use paid tier or HuggingFace Spaces for that.

---

## 🚀 Deployment Options

| Option | Models | RAM Needed | Cost |
|--------|--------|------------|------|
| **Free tier (Render/Railway)** | XGB + LGB | ~200 MB | Free |
| **Paid tier ($7/mo)** | XGB + LGB + BERT | ~1 GB | $7/mo |
| **HuggingFace Spaces** | Full ensemble | GPU available | Free |

The `ml_predictor.py` auto-detects whether BERT is available and gracefully falls back to XGB+LGB.

---

## 🔧 Training Notebook Details

The Colab notebook (`SIH26106_Email_Threat_Detection_Training.ipynb`) trains 3 models:

| Model | Estimators | Key Params | Expected Time |
|-------|-----------|------------|---------------|
| XGBoost | 400 trees | depth=7, lr=0.08 | ~5 min |
| LightGBM | 500 trees | leaves=63, lr=0.05 | ~3 min |
| DistilBERT | 3 epochs | lr=2e-5, batch=32 | ~45-90 min |

**Datasets used** (all in Google Drive):`
```
MyDrive/datasets/
├── Phishing_Email.csv                          (52 MB, ~18K emails)
├── phishing_legitimate_emails.csv              (0.8 MB, ~7K emails)
├── human_legit.csv                             (4.4 MB, 1K emails)
├── human_phishing.csv                          (1.3 MB, 1K emails)
├── llm_legit.csv                               (0.6 MB, 1K emails)
├── llm_phishing.csv                            (0.7 MB, 1K emails)
└── mail_data.csv                               (0.5 MB, spam dataset)
```

**Bug fixes applied** (vs earlier notebook versions):
- `llm_phishing.csv` ParserError — unquoted commas in text fixed with custom CSV parser
- `torch.cuda.amp.GradScaler()` → `torch.amp.GradScaler("cuda")` (PyTorch 2.4+ deprecation)
- `torch.cuda.amp.autocast()` → `torch.amp.autocast("cuda")` (same)
- `nltk.download('punkt')` → `nltk.download('punkt_tab')` (NLTK 3.9+ deprecation)
- `use_label_encoder=False` removed from XGBoost (removed in XGBoost 2.0+)

---

## 🏁 How to Train (Step-by-Step for Teammates)

1. Go to [Google Drive](https://drive.google.com/drive/folders/1MqyAdNHZFGVQzfDx5VwszbqbiEgm-Wg0?usp=drive_link) → make sure you can see all 7 CSV files
2. Open [the Colab notebook](https://colab.research.google.com/drive/1Rqz3TkPnmXebt8jz39oWvjM6Q-P4J-T1?usp=sharing)
3. **Enable GPU**: Runtime → Change runtime type → **T4 GPU** → Save
4. **Runtime → Run all** (Ctrl+F9)
5. Wait for all cells to finish — models save to `MyDrive/trained_models/`
6. Download the `.pkl` files from `MyDrive/trained_models/` and place in `backend/ml/models/`

> ⚠️ If you get errors, check the **Bug fixes** section above.
> The most common issue was `ParserError` on `llm_phishing.csv` — already fixed in this notebook.

---

## 👥 Team: Mutex

| Member | Track |
|--------|-------|
| Sabarish | ML Integration + Architecture |
| Vignesh | GeoLocation |
| Shafeeq | Forensic Intelligence |
| Rohith | Dashboard + Demo |
