
# ============================================================
#  SIH26106 - Email Threat Classifier Inference Module
#  Drop this file into: backend/ml/email_classifier.py
# ============================================================
import joblib, json, re, torch
import numpy as np
from scipy.sparse import hstack, csr_matrix
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

MODEL_DIR = "ml/models"
THRESHOLD = 0.75

tfidf      = joblib.load(f"{MODEL_DIR}/tfidf_vectorizer.pkl")
xgb_model  = joblib.load(f"{MODEL_DIR}/xgb_email_threat_model.pkl")
lgb_model  = joblib.load(f"{MODEL_DIR}/lgb_email_threat_model.pkl")
feat_cols  = json.load(open(f"{MODEL_DIR}/feature_cols.json"))
device     = torch.device("cuda" if torch.cuda.is_available() else "cpu")
bert_tok   = DistilBertTokenizerFast.from_pretrained(f"{MODEL_DIR}/distilbert_email_threat")
bert_model = DistilBertForSequenceClassification.from_pretrained(
    f"{MODEL_DIR}/distilbert_email_threat"
).to(device).eval()

PHISHING_KEYWORDS = [
    "verify", "account", "suspended", "click here", "urgent", "winner",
    "prize", "free", "limited time", "act now", "immediately", "confirm",
    "password", "login", "bank", "paypal", "update your", "congratulations",
]

def clean_text(text):
    text = re.sub(r"http\\S+|www\\S+", " URL ", text.lower())
    text = re.sub(r"\\S+@\\S+", " EMAIL ", text)
    text = re.sub(r"[^a-z\\s]", " ", text)
    return re.sub(r"\\s+", " ", text).strip()

def extract_features(text):
    t, tl = str(text), str(text).lower()
    return {
        "char_count":        len(t),
        "word_count":        len(t.split()),
        "url_count":         len(re.findall(r"http\\S+|www\\S+", tl)),
        "email_count":       len(re.findall(r"\\S+@\\S+", tl)),
        "exclaim_count":     t.count("!"),
        "question_count":    t.count("?"),
        "caps_ratio":        sum(1 for c in t if c.isupper()) / max(len(t), 1),
        "digit_ratio":       sum(1 for c in t if c.isdigit()) / max(len(t), 1),
        "html_tag_count":    len(re.findall(r"<[^>]+>", tl)),
        "phishing_kw_count": sum(1 for kw in PHISHING_KEYWORDS if kw in tl),
        "has_ip_addr":       int(bool(re.search(r"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}", t))),
        "has_urgency":       int(any(w in tl for w in ["urgent", "immediately", "act now", "expires"])),
        "has_money_words":   int(any(w in tl for w in ["$", "bitcoin", "prize", "reward", "million"])),
        "has_account_words": int(any(w in tl for w in ["verify", "password", "login", "account"])),
        "unique_word_ratio": len(set(t.lower().split())) / max(len(t.split()), 1),
        "avg_word_len":      np.mean([len(w) for w in t.split()]) if t.split() else 0,
        "suspicious_tld":    int(bool(re.search(r"\\.(xyz|tk|ml|ga|cf|pw|top|click|win|loan)", tl))),
    }

def classify_email(email_text: str) -> dict:
    clean  = clean_text(email_text)
    feats  = extract_features(email_text)
    X_tfidf = tfidf.transform([clean])
    X_hand  = csr_matrix([[feats[f] for f in feat_cols]])
    X       = hstack([X_tfidf, X_hand])

    xgb_prob = float(xgb_model.predict_proba(X)[0][1])
    lgb_prob = float(lgb_model.predict_proba(X)[0][1])

    enc = bert_tok(email_text, truncation=True, padding=True,
                   max_length=256, return_tensors="pt").to(device)
    with torch.no_grad():
        logits = bert_model(**enc).logits
        bert_prob = float(torch.softmax(logits, dim=1)[0][1])

    ensemble_prob = 0.6 * bert_prob + 0.2 * xgb_prob + 0.2 * lgb_prob
    is_phishing   = ensemble_prob >= 0.5
    confidence    = ensemble_prob if is_phishing else (1 - ensemble_prob)

    risk = "HIGH" if ensemble_prob > 0.8 else ("MEDIUM" if ensemble_prob > 0.5 else "LOW")
    needs_gemini = confidence < THRESHOLD

    return {
        "label":       "phishing" if is_phishing else "legitimate",
        "confidence":  round(confidence, 4),
        "model_used":  "gemini_fallback" if needs_gemini else "bert_ensemble",
        "xgb_score":   round(xgb_prob, 4),
        "lgb_score":   round(lgb_prob, 4),
        "bert_score":  round(bert_prob, 4),
        "ensemble":    round(ensemble_prob, 4),
        "risk_level":  risk,
        "needs_gemini_review": needs_gemini,
        "features":    feats
    }
