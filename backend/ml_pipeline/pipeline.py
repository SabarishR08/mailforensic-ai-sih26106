"""
Phishing Detection Pipeline
Orchestrates the entire ML pipeline from data loading to model evaluation
"""

import pickle
import os
from typing import Dict, Any, Tuple
import logging

from .data_loader import DataLoader
from .feature_engineering import FeatureEngineer
from .model_builder import ModelBuilder
from .evaluator import ModelEvaluator

logger = logging.getLogger(__name__)


class PhishingDetectionPipeline:
    """Complete end-to-end pipeline for phishing detection"""

    def __init__(self, data_dir: str = "data", model_dir: str = "backend/ml_models",
                 optimize_for: str = 'balanced', random_state: int = 42):
        self.data_dir = data_dir
        self.model_dir = model_dir
        self.optimize_for = optimize_for
        self.random_state = random_state

        os.makedirs(model_dir, exist_ok=True)

        self.data_loader = DataLoader(data_dir)
        self.feature_engineer = FeatureEngineer()
        self.model_builder = ModelBuilder(optimize_for, random_state)
        self.evaluator = ModelEvaluator()

    def train_email_model(self, balance_data=True, use_advanced=True, calibrate=True) -> Tuple[Any, Dict]:
        logger.info("\n" + "="*80)
        logger.info("TRAINING EMAIL PHISHING DETECTION MODEL")
        logger.info("="*80 + "\n")

        emails, labels = self.data_loader.load_email_data(balance=balance_data)
        data_splits = self.data_loader.split_data(emails, labels, test_size=0.15, val_size=0.10)

        logger.info(f"  Training: {len(data_splits['X_train']):,} | Val: {len(data_splits['X_val']):,} | Test: {len(data_splits['X_test']):,}")

        self.feature_engineer.fit_email_features(data_splits['X_train'])
        X_train = self.feature_engineer.transform_email_features(data_splits['X_train'])
        X_val = self.feature_engineer.transform_email_features(data_splits['X_val'])
        X_test = self.feature_engineer.transform_email_features(data_splits['X_test'])

        model = self.model_builder.build_email_model(advanced=use_advanced)
        model.fit(X_train, data_splits['y_train'])

        if calibrate and len(data_splits['X_val']) > 0:
            model = self.model_builder.calibrate_model(model, X_val, data_splits['y_val'])

        if len(data_splits['X_val']) > 0:
            self.evaluator.evaluate(model, X_val, data_splits['y_val'], "Validation")
        test_metrics = self.evaluator.evaluate(model, X_test, data_splits['y_test'], "Test")

        model_path = os.path.join(self.model_dir, "email_model.pkl")
        vectorizer_path = os.path.join(self.model_dir, "email_vectorizer.pkl")
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(self.feature_engineer, f)

        logger.info(f"  Model saved: {model_path}")
        logger.info(f"  Feature engineer saved: {vectorizer_path}")
        return model, test_metrics

    def train_url_model(self, balance_data=True, use_advanced=True, calibrate=True) -> Tuple[Any, Dict]:
        logger.info("\n" + "="*80)
        logger.info("TRAINING URL PHISHING DETECTION MODEL")
        logger.info("="*80 + "\n")

        urls, labels = self.data_loader.load_url_data(balance=balance_data)
        if len(urls) == 0:
            logger.error("No URL data loaded.")
            return None, {}

        data_splits = self.data_loader.split_data(urls, labels, test_size=0.15, val_size=0.10)
        logger.info(f"  Training: {len(data_splits['X_train']):,} | Val: {len(data_splits['X_val']):,} | Test: {len(data_splits['X_test']):,}")

        self.feature_engineer.fit_url_features(data_splits['X_train'])
        X_train = self.feature_engineer.transform_url_features(data_splits['X_train'])
        X_val = self.feature_engineer.transform_url_features(data_splits['X_val'])
        X_test = self.feature_engineer.transform_url_features(data_splits['X_test'])

        model = self.model_builder.build_url_model(advanced=use_advanced)
        model.fit(X_train, data_splits['y_train'])

        if calibrate and len(data_splits['X_val']) > 0:
            model = self.model_builder.calibrate_model(model, X_val, data_splits['y_val'])

        if len(data_splits['X_val']) > 0:
            self.evaluator.evaluate(model, X_val, data_splits['y_val'], "Validation")
        test_metrics = self.evaluator.evaluate(model, X_test, data_splits['y_test'], "Test")

        model_path = os.path.join(self.model_dir, "url_model.pkl")
        vectorizer_path = os.path.join(self.model_dir, "url_vectorizer.pkl")
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(self.feature_engineer, f)

        logger.info(f"  Model saved: {model_path}")
        logger.info(f"  Feature engineer saved: {vectorizer_path}")
        return model, test_metrics

    def train_all(self, balance_data=True, use_advanced=True, calibrate=True) -> Dict:
        results = {}
        email_model, email_metrics = self.train_email_model(balance_data, use_advanced, calibrate)
        results['email'] = {'model': email_model, 'metrics': email_metrics}

        url_model, url_metrics = self.train_url_model(balance_data, use_advanced, calibrate)
        results['url'] = {'model': url_model, 'metrics': url_metrics}

        return results
