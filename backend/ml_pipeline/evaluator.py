"""
Model Evaluation Module
Comprehensive evaluation with metrics, confusion matrix, and FP/FN analysis
"""

import numpy as np
from typing import Dict, Any
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
import logging

logger = logging.getLogger(__name__)


class ModelEvaluator:
    """Comprehensive model evaluation"""

    def evaluate(self, model, X, y, dataset_name: str = "Test") -> Dict[str, Any]:
        y_pred = model.predict(X)

        metrics = {
            'accuracy': accuracy_score(y, y_pred),
            'precision': precision_score(y, y_pred, pos_label='phishing', zero_division=0),
            'recall': recall_score(y, y_pred, pos_label='phishing', zero_division=0),
            'f1': f1_score(y, y_pred, pos_label='phishing', zero_division=0),
        }

        cm = confusion_matrix(y, y_pred, labels=['legitimate', 'phishing'])
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        metrics['true_positives'] = int(tp)
        metrics['true_negatives'] = int(tn)
        metrics['false_positives'] = int(fp)
        metrics['false_negatives'] = int(fn)

        logger.info(f"\n{'='*60}")
        logger.info(f"{dataset_name} Set Evaluation")
        logger.info(f"{'='*60}")
        logger.info(f"  Accuracy:  {metrics['accuracy']*100:.2f}%")
        logger.info(f"  Precision: {metrics['precision']*100:.2f}%")
        logger.info(f"  Recall:    {metrics['recall']*100:.2f}%")
        logger.info(f"  F1-Score:  {metrics['f1']*100:.2f}%")
        logger.info(f"  TP: {tp} | TN: {tn} | FP: {fp} | FN: {fn}")
        logger.info(f"{'='*60}\n")

        return metrics
