"""
ML Prediction Service
Loads trained models and provides prediction interface for the platform
"""

import pickle
import os
import numpy as np
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)

MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'ml_models')


class MLPredictor:
    """Unified predictor for email and URL phishing detection"""

    def __init__(self, models_dir: str = None):
        self.models_dir = models_dir or MODELS_DIR
        self.email_model = None
        self.email_feature_engineer = None
        self.url_model = None
        self.url_feature_engineer = None
        self._load_models()

    def _load_models(self):
        """Load all available models"""
        email_model_path = os.path.join(self.models_dir, 'email_model.pkl')
        email_feat_path = os.path.join(self.models_dir, 'email_vectorizer.pkl')
        url_model_path = os.path.join(self.models_dir, 'url_model.pkl')
        url_feat_path = os.path.join(self.models_dir, 'url_vectorizer.pkl')

        if os.path.exists(email_model_path) and os.path.exists(email_feat_path):
            try:
                with open(email_model_path, 'rb') as f:
                    self.email_model = pickle.load(f)
                with open(email_feat_path, 'rb') as f:
                    self.email_feature_engineer = pickle.load(f)
                logger.info("Email ML model loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load email model: {e}")
        else:
            logger.warning("Email model files not found — run training first")

        if os.path.exists(url_model_path) and os.path.exists(url_feat_path):
            try:
                with open(url_model_path, 'rb') as f:
                    self.url_model = pickle.load(f)
                with open(url_feat_path, 'rb') as f:
                    self.url_feature_engineer = pickle.load(f)
                logger.info("URL ML model loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load url model: {e}")
        else:
            logger.warning("URL model files not found — run training first")

    def is_email_model_loaded(self) -> bool:
        return self.email_model is not None and self.email_feature_engineer is not None

    def is_url_model_loaded(self) -> bool:
        return self.url_model is not None and self.url_feature_engineer is not None

    def predict_email(self, email_text: str) -> Tuple[str, float]:
        """Predict if email text is phishing"""
        if not self.is_email_model_loaded():
            return "unknown", 0.5

        try:
            if hasattr(self.email_feature_engineer, 'transform_email_features'):
                X = self.email_feature_engineer.transform_email_features([email_text])
            else:
                X = self.email_feature_engineer.transform([email_text])

            prediction = self.email_model.predict(X)[0]

            if hasattr(self.email_model, 'predict_proba'):
                proba = self.email_model.predict_proba(X)[0]
                classes = list(self.email_model.classes_)
                confidence = proba[classes.index(prediction)]
            else:
                confidence = 0.8

            return str(prediction), float(confidence)
        except Exception as e:
            logger.error(f"Email prediction error: {e}")
            return "error", 0.5

    def predict_url(self, url: str) -> Tuple[str, float]:
        """Predict if URL is phishing"""
        if not self.is_url_model_loaded():
            return "unknown", 0.5

        try:
            if hasattr(self.url_feature_engineer, 'transform_url_features'):
                X = self.url_feature_engineer.transform_url_features([url])
            else:
                X = self.url_feature_engineer.transform([url])

            prediction = self.url_model.predict(X)[0]

            if hasattr(self.url_model, 'predict_proba'):
                proba = self.url_model.predict_proba(X)[0]
                classes = list(self.url_model.classes_)
                confidence = proba[classes.index(prediction)]
            else:
                confidence = 0.8

            return str(prediction), float(confidence)
        except Exception as e:
            logger.error(f"URL prediction error: {e}")
            return "error", 0.5


# Singleton
_predictor: Optional[MLPredictor] = None


def get_ml_predictor() -> MLPredictor:
    global _predictor
    if _predictor is None:
        _predictor = MLPredictor()
    return _predictor
