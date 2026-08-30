"""
ML Prediction Service — SIH26106 Trained Models
Loads XGBoost + LightGBM + DistilBERT ensemble from Colab training.
60% BERT + 20% XGBoost + 20% LightGBM weighted ensemble.
"""

import joblib
import json
import re
import os
import logging
import numpy as np
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

# Resolve models dir relative to this file → backend/ml/models/
MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'ml', 'models')

PHISHING_KEYWORDS = [
    "verify", "account", "suspended", "click here", "urgent", "winner",
    "prize", "free", "limited time", "act now", "immediately", "confirm",
    "password", "login", "bank", "paypal", "update your", "congratulations",
]

# Classification threshold — 0.6 + heuristic override for false positives
# Emails scoring 0.5-0.6 are labeled "suspicious" (not phishing, not legitimate)
PHISHING_THRESHOLD = 0.6

# Feature columns used during training (19 manual features)
MANUAL_FEATURE_COLS = [
    "char_count", "word_count", "url_count", "email_count",
    "exclaim_count", "question_count", "caps_ratio", "digit_ratio",
    "html_tag_count", "phishing_kw_count", "credential_threat_count",
    "account_word_count", "has_ip_addr", "has_urgency", "has_money_words",
    "has_credential_threat", "unique_word_ratio", "avg_word_len",
    "suspicious_tld",
]


# Known legitimate sender domains (security newsletters, SaaS, tech companies)
# These domains are recognized as NOT phishing even if content contains threat keywords
KNOWN_LEGITIMATE_DOMAINS = [
    # Email providers
    'google.com', 'gmail.com', 'googlemail.com',
    # Cloud / SaaS
    'fly.io', 'vercel.com', 'render.com', 'github.com', 'gitlab.com',
    'atlassian.com', 'slack.com', 'zoom.us', 'loom.com',
    'stripe.com', 'heroku.com', 'digitalocean.com',
    # Security newsletters
    'darkreading.com', 'securityweek.com', 'bleepingcomputer.com',
    'threatpost.com', 'scmagazine.com', 'cyberscoop.com',
    # Enterprise
    'microsoft.com', 'apple.com', 'amazon.com', 'meta.com',
    'cisco.com', 'vmware.com', 'oracle.com',
    # Freebuff / internal
    'freebuff.io', 'freebuff.com',
]


def _check_legitimate_signals(text: str) -> dict:
    """
    Heuristic check for obviously legitimate emails.
    Returns {'is_legitimate': bool, 'reason': str, 'signals': list}.
    Used to override ML when the email has ZERO phishing indicators.
    """
    tl = text.lower()
    signals = []
    anti_signals = []

    # --- Sender domain check (strongest signal) ---
    from_match = re.search(r'from:\s*(\S+@([\w.-]+))', tl)
    if from_match:
        sender_domain = from_match.group(2)
        if any(sender_domain.endswith(d) for d in KNOWN_LEGITIMATE_DOMAINS):
            signals.append('known_legitimate_domain')

    # --- Newsletter / mailing list signals ---
    if 'unsubscribe' in tl or 'opt out' in tl or 'opt-out' in tl:
        signals.append('has_unsubscribe')
    if any(w in tl for w in ['newsletter', 'digest', 'weekly roundup', 'daily briefing',
                              'threat intel', 'threat intelligence', 'security advisory',
                              'vulnerability', 'cve-', 'insights']):
        signals.append('newsletter_content')
    if re.search(r'\bfrom\b.*\b(cisco|github|gitlab|atlassian|microsoft|apple|google|fly\.io|vercel|render)\b', tl):
        signals.append('known_brand_mention')

    # --- Pro-legitimate signals (these are NORMAL in legit emails) ---
    if not re.search(r'http\S+|www\S+', tl):
        signals.append('no_urls')
    if not any(w in tl for w in ['urgent', 'immediately', 'act now', 'expires', 'last chance', 'suspended', 'locked']):
        signals.append('no_urgency')
    if not any(phrase in tl for phrase in [
        'verify your password', 'confirm your login', 'reset your password',
        'click here to verify', 'click here to confirm', 'click here to update',
        'confirm your identity', 'verify your identity',
        'send your bank', 'wire transfer', 'processing fee',
    ]):
        signals.append('no_credential_request')
    if not re.search(r'\.(xyz|tk|ml|ga|cf|pw|top|click|win|loan)', tl):
        signals.append('no_suspicious_tld')
    if text.count('!') <= 1:
        signals.append('low_exclamation')
    if sum(1 for c in text if c.isupper()) / max(len(text), 1) < 0.15:
        signals.append('normal_caps')

    # --- Anti-legitimate signals (these suggest phishing) ---
    # Only count strong anti-signals; weak ones like 'contains_ip' are ignored for newsletters
    has_newsletter_signal = 'newsletter_content' in signals or 'has_unsubscribe' in signals or 'known_legitimate_domain' in signals

    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text):
        if not has_newsletter_signal:
            anti_signals.append('contains_ip_address')
    if any(w in tl for w in ['winner', 'prize', 'congratulations', 'claim your', 'million dollars']):
        anti_signals.append('scam_keywords')
    if re.search(r'send.*\$|\$.*send|bank detail|credit card.*number|social security', tl):
        anti_signals.append('requests_sensitive_data')
    if any(phrase in tl for phrase in ['dear customer', 'dear user', 'dear valued']):
        anti_signals.append('generic_greeting')
    # Crypto/financial fraud signals
    if any(w in tl for w in ['bitcoin', 'btc', 'eth', 'crypto', 'wallet address', 'send.*btc']):
        anti_signals.append('crypto_fraud')
    if any(w in tl for w in ['guaranteed returns', 'guaranteed profit', 'guaranteed returns', 'risk-free', 'double your money']):
        anti_signals.append('financial_scam')
    if re.search(r'send.*\d|transfer.*\d|wire.*\d|pay.*\d.*fee', tl):
        anti_signals.append('requests_money_transfer')
    if re.search(r'limited spots|act now|expires in|only \d+ left', tl):
        anti_signals.append('artificial_urgency')
    # Suspicious sender patterns
    if re.search(r'secur[ie]ty@|admin@|support@|noreply@', tl) and re.search(r'\.(xyz|tk|ml|ga|cf|pw|top|click|win|loan)', tl):
        anti_signals.append('suspicious_sender_domain')

    # --- Decision ---
    # Case 1: Known legitimate domain OR strong newsletter signals -> legitimate
    if 'known_legitimate_domain' in signals:
        is_legitimate = True
        reason = f'known legitimate sender domain'
    elif len(signals) >= 3 and has_newsletter_signal:
        is_legitimate = True
        reason = f'{len(signals)} signals + newsletter pattern'
    elif len(signals) >= 5 and len(anti_signals) == 0:
        is_legitimate = True
        reason = f'{len(signals)} legit signals, {len(anti_signals)} anti-signals'
    else:
        is_legitimate = False
        reason = f'{len(signals)} signals, {len(anti_signals)} anti-signals'

    return {
        'is_legitimate': is_legitimate,
        'reason': reason,
        'signals': signals,
        'anti_signals': anti_signals,
    }


def _clean_text(text: str) -> str:
    """Clean text for TF-IDF vectorization."""
    text = re.sub(r'http\S+|www\S+', ' URL ', text.lower())
    text = re.sub(r'\S+@\S+', ' EMAIL ', text)
    text = re.sub(r'[^a-z\s]', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()


def _extract_manual_features(text: str) -> dict:
    """Extract the 19 manual features used during Colab training."""
    t = str(text)
    tl = t.lower()
    return {
        "char_count": len(t),
        "word_count": len(t.split()),
        "url_count": len(re.findall(r'http\S+|www\S+', tl)),
        "email_count": len(re.findall(r'\S+@\S+', tl)),
        "exclaim_count": t.count("!"),
        "question_count": t.count("?"),
        "caps_ratio": sum(1 for c in t if c.isupper()) / max(len(t), 1),
        "digit_ratio": sum(1 for c in t if c.isdigit()) / max(len(t), 1),
        "html_tag_count": len(re.findall(r'<[^>]+>', tl)),
        "phishing_kw_count": sum(1 for kw in PHISHING_KEYWORDS if kw in tl),
        "credential_threat_count": sum(
            1 for kw in ["password", "login", "credential", "ssn", "credit card"]
            if kw in tl
        ),
        "account_word_count": sum(
            1 for kw in ["verify", "password", "login", "account", "confirm"]
            if kw in tl
        ),
        "has_ip_addr": int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', t))),
        "has_urgency": int(any(w in tl for w in ["urgent", "immediately", "act now", "expires"])),
        "has_money_words": int(any(w in tl for w in ["$", "bitcoin", "prize", "reward", "million"])),
        "has_credential_threat": int(any(w in tl for w in ["password", "verify", "login", "credential"])),
        "unique_word_ratio": len(set(t.lower().split())) / max(len(t.split()), 1),
        "avg_word_len": np.mean([len(w) for w in t.split()]) if t.split() else 0,
        "suspicious_tld": int(bool(re.search(r'\.(xyz|tk|ml|ga|cf|pw|top|click|win|loan)', tl))),
    }


class MLPredictor:
    """Ensemble predictor: XGBoost + LightGBM + DistilBERT"""

    def __init__(self, models_dir: str = None):
        self.models_dir = models_dir or MODELS_DIR
        self.tfidf = None
        self.xgb_model = None
        self.lgb_model = None
        self.bert_tokenizer = None
        self.bert_model = None
        self.feat_cols = MANUAL_FEATURE_COLS
        self.device = None
        self._loaded = False
        self._load_models()

    def _load_models(self):
        """Load all trained model artifacts."""
        try:
            # TF-IDF vectorizer
            tfidf_path = os.path.join(self.models_dir, 'tfidf_vectorizer.pkl')
            if os.path.exists(tfidf_path):
                self.tfidf = joblib.load(tfidf_path)
                logger.info("✅ TF-IDF vectorizer loaded")

            # Feature columns (may override defaults)
            feat_cols_path = os.path.join(self.models_dir, 'feature_cols.json')
            if os.path.exists(feat_cols_path):
                with open(feat_cols_path) as f:
                    self.feat_cols = json.load(f)

            # XGBoost
            xgb_path = os.path.join(self.models_dir, 'xgb_email_threat_model.pkl')
            if os.path.exists(xgb_path):
                self.xgb_model = joblib.load(xgb_path)
                logger.info("✅ XGBoost model loaded")

            # LightGBM
            lgb_path = os.path.join(self.models_dir, 'lgb_email_threat_model.pkl')
            if os.path.exists(lgb_path):
                self.lgb_model = joblib.load(lgb_path)
                logger.info("✅ LightGBM model loaded")

            # DistilBERT (optional — requires torch + transformers)
            bert_dir = os.path.join(self.models_dir, 'distilbert_email_threat')
            if os.path.exists(os.path.join(bert_dir, 'config.json')):
                try:
                    import torch
                    from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

                    self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                    self.bert_tokenizer = DistilBertTokenizerFast.from_pretrained(bert_dir)
                    self.bert_model = DistilBertForSequenceClassification.from_pretrained(
                        bert_dir
                    ).to(self.device).eval()
                    logger.info(f"✅ DistilBERT model loaded on {self.device}")
                except ImportError as e:
                    logger.warning(f"DistilBERT unavailable (torch/transformers not installed): {e}")
                except Exception as e:
                    logger.error(f"Failed to load DistilBERT: {e}")
            else:
                logger.info("ℹ️  No DistilBERT model found — using XGB+LGB ensemble only")

            self._loaded = any([self.tfidf, self.xgb_model, self.lgb_model])
            if self._loaded:
                logger.info(
                    f"ML Predictor ready — models: "
                    f"{'XGB' if self.xgb_model else ''} "
                    f"{'LGB' if self.lgb_model else ''} "
                    f"{'BERT' if self.bert_model else ''}"
                )
            else:
                logger.warning("⚠️  No models loaded — predictions will return 'unknown'")

        except Exception as e:
            logger.error(f"Model loading failed: {e}")

    def is_email_model_loaded(self) -> bool:
        return self._loaded

    def predict_email(self, email_text: str) -> Tuple[str, float]:
        """
        Predict if email text is phishing using the trained ensemble.
        Returns (label, confidence) where label is 'phishing' or 'legitimate'.
        """
        if not self._loaded:
            return "unknown", 0.5

        try:
            xgb_prob = 0.5
            lgb_prob = 0.5
            bert_prob = 0.5

            # XGBoost + LightGBM on TF-IDF + manual features
            if self.tfidf and (self.xgb_model or self.lgb_model):
                clean = _clean_text(email_text)
                feats = _extract_manual_features(email_text)

                X_tfidf = self.tfidf.transform([clean])
                try:
                    from scipy.sparse import hstack, csr_matrix
                    X_hand = csr_matrix([[feats.get(f, 0) for f in self.feat_cols]])
                    X = hstack([X_tfidf, X_hand])
                except ImportError:
                    X = X_tfidf

                if self.xgb_model:
                    xgb_prob = float(self.xgb_model.predict_proba(X)[0][1])
                if self.lgb_model:
                    lgb_prob = float(self.lgb_model.predict_proba(X)[0][1])

            # DistilBERT (needs torch)
            if self.bert_model and self.bert_tokenizer:
                import torch
                enc = self.bert_tokenizer(
                    email_text, truncation=True, padding=True,
                    max_length=256, return_tensors="pt"
                ).to(self.device)
                with torch.no_grad():
                    logits = self.bert_model(**enc).logits
                    bert_prob = float(torch.softmax(logits, dim=1)[0][1])

            # Weighted ensemble
            has_bert = self.bert_model is not None
            if has_bert:
                ensemble_prob = 0.6 * bert_prob + 0.2 * xgb_prob + 0.2 * lgb_prob
            elif self.xgb_model and self.lgb_model:
                ensemble_prob = 0.5 * xgb_prob + 0.5 * lgb_prob
            elif self.xgb_model:
                ensemble_prob = xgb_prob
            elif self.lgb_model:
                ensemble_prob = lgb_prob
            else:
                ensemble_prob = 0.5

            # Classification with threshold
            if ensemble_prob >= PHISHING_THRESHOLD:
                label = "phishing"
                confidence = ensemble_prob
            elif ensemble_prob >= 0.5:
                label = "suspicious"  # Borderline — not clearly phishing or legit
                confidence = 1 - abs(ensemble_prob - 0.5) * 2  # Confidence decreases toward 0.5
            else:
                label = "legitimate"
                confidence = 1 - ensemble_prob

            # Post-processing: override ML if email has strong legitimate signals
            # This catches false positives where TF-IDF over-weights "account"/"sign in"
            legit_check = _check_legitimate_signals(email_text)
            if label == "phishing" and legit_check['is_legitimate']:
                label = "legitimate"
                confidence = 0.85  # High confidence override
                logger.info(f"ML override: {legit_check['reason']}")

            return label, float(round(confidence, 4))

        except Exception as e:
            logger.error(f"Email prediction error: {e}")
            return "error", 0.5

    def predict_email_detailed(self, email_text: str) -> dict:
        """
        Detailed prediction with per-model scores.
        Used by the forensic report and risk scoring.
        """
        if not self._loaded:
            return {
                "label": "unknown", "confidence": 0.5,
                "ensemble": 0.5, "xgb_score": 0.5, "lgb_score": 0.5,
                "bert_score": 0.5, "model_used": "none",
            }

        try:
            xgb_prob = 0.5
            lgb_prob = 0.5
            bert_prob = 0.5

            if self.tfidf and (self.xgb_model or self.lgb_model):
                clean = _clean_text(email_text)
                feats = _extract_manual_features(email_text)
                X_tfidf = self.tfidf.transform([clean])
                try:
                    from scipy.sparse import hstack, csr_matrix
                    X_hand = csr_matrix([[feats.get(f, 0) for f in self.feat_cols]])
                    X = hstack([X_tfidf, X_hand])
                except ImportError:
                    X = X_tfidf

                if self.xgb_model:
                    xgb_prob = float(self.xgb_model.predict_proba(X)[0][1])
                if self.lgb_model:
                    lgb_prob = float(self.lgb_model.predict_proba(X)[0][1])

            if self.bert_model and self.bert_tokenizer:
                import torch
                enc = self.bert_tokenizer(
                    email_text, truncation=True, padding=True,
                    max_length=256, return_tensors="pt"
                ).to(self.device)
                with torch.no_grad():
                    logits = self.bert_model(**enc).logits
                    bert_prob = float(torch.softmax(logits, dim=1)[0][1])

            has_bert = self.bert_model is not None
            if has_bert:
                ensemble_prob = 0.6 * bert_prob + 0.2 * xgb_prob + 0.2 * lgb_prob
                model_used = "bert_ensemble"
            elif self.xgb_model and self.lgb_model:
                ensemble_prob = 0.5 * xgb_prob + 0.5 * lgb_prob
                model_used = "xgb_lgb_ensemble"
            elif self.xgb_model:
                ensemble_prob = xgb_prob
                model_used = "xgboost_only"
            else:
                ensemble_prob = lgb_prob
                model_used = "lightgbm_only"

            # Classification with threshold
            if ensemble_prob >= PHISHING_THRESHOLD:
                label = "phishing"
                confidence = ensemble_prob
            elif ensemble_prob >= 0.5:
                label = "suspicious"
                confidence = 1 - abs(ensemble_prob - 0.5) * 2
            else:
                label = "legitimate"
                confidence = 1 - ensemble_prob

            # Post-processing override
            legit_check = _check_legitimate_signals(email_text)
            if label == "phishing" and legit_check['is_legitimate']:
                label = "legitimate"
                confidence = 0.85
                model_used = "heuristic_override"

            return {
                "label": label,
                "confidence": round(confidence, 4),
                "ensemble": round(ensemble_prob, 4),
                "xgb_score": round(xgb_prob, 4),
                "lgb_score": round(lgb_prob, 4),
                "bert_score": round(bert_prob, 4),
                "model_used": model_used,
            }

        except Exception as e:
            logger.error(f"Detailed prediction error: {e}")
            return {
                "label": "error", "confidence": 0.5,
                "ensemble": 0.5, "xgb_score": 0.5, "lgb_score": 0.5,
                "bert_score": 0.5, "model_used": "error",
            }

    def predict_url(self, url: str) -> Tuple[str, float]:
        """Predict if a URL is phishing (placeholder — no URL model in Colab training)."""
        # The Colab notebook focused on email detection.
        # URL detection uses the existing threat_intelligence service (VT/SafeBrowsing/PhishTank).
        return "unknown", 0.5


# Singleton
_predictor: Optional[MLPredictor] = None


def get_ml_predictor() -> MLPredictor:
    global _predictor
    if _predictor is None:
        _predictor = MLPredictor()
    return _predictor
