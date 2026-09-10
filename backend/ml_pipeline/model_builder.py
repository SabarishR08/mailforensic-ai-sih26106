"""
Advanced Model Builder Module
Creates optimized ensemble models with proper calibration
"""

import numpy as np
from typing import Any, Dict, Tuple
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import cross_val_score, StratifiedKFold
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
import logging

logger = logging.getLogger(__name__)


class ModelBuilder:
    """Advanced model builder with optimal configuration"""

    def __init__(self, optimize_for: str = 'balanced', random_state: int = 42):
        self.optimize_for = optimize_for
        self.random_state = random_state
        self.class_weight = self._get_class_weight()

    def _get_class_weight(self):
        if self.optimize_for == 'precision':
            return {0: 1, 1: 2}
        elif self.optimize_for == 'recall':
            return {0: 2, 1: 1}
        return 'balanced'

    def build_email_model(self, advanced: bool = True) -> Any:
        logger.info(f"Building email model (advanced={advanced})...")
        model = self._build_stacking_ensemble() if advanced else self._build_voting_ensemble()
        logger.info(f"Email model built: {type(model).__name__}")
        return model

    def build_url_model(self, advanced: bool = True) -> Any:
        logger.info(f"Building URL model (advanced={advanced})...")
        model = self._build_stacking_ensemble() if advanced else self._build_voting_ensemble()
        logger.info(f"URL model built: {type(model).__name__}")
        return model

    def _build_voting_ensemble(self):
        from sklearn.ensemble import VotingClassifier, GradientBoostingClassifier
        estimators = [
            ('lr', LogisticRegression(max_iter=1000, C=1.0, solver='saga',
                                     class_weight=self.class_weight, random_state=self.random_state, n_jobs=-1)),
            ('rf', RandomForestClassifier(n_estimators=300, max_depth=35, min_samples_split=4,
                                         min_samples_leaf=2, max_features='sqrt',
                                         class_weight=self.class_weight, random_state=self.random_state, n_jobs=-1)),
            ('xgb', XGBClassifier(n_estimators=300, learning_rate=0.08, max_depth=8,
                                  min_child_weight=2, subsample=0.8, colsample_bytree=0.8,
                                  gamma=0.1, random_state=self.random_state, n_jobs=-1, eval_metric='logloss')),
            ('lgbm', LGBMClassifier(n_estimators=300, learning_rate=0.08, max_depth=8,
                                    num_leaves=64, min_child_samples=20, subsample=0.8,
                                    colsample_bytree=0.8, random_state=self.random_state, n_jobs=-1, verbose=-1)),
        ]
        return VotingClassifier(estimators=estimators, voting='soft', n_jobs=-1)

    def _build_stacking_ensemble(self):
        base_models = [
            ('lr', LogisticRegression(max_iter=1000, C=1.0, solver='saga',
                                     class_weight=self.class_weight, random_state=self.random_state, n_jobs=-1)),
            ('rf', RandomForestClassifier(n_estimators=200, max_depth=30, min_samples_split=4,
                                         min_samples_leaf=2, max_features='sqrt',
                                         class_weight=self.class_weight, random_state=self.random_state, n_jobs=-1)),
            ('xgb', XGBClassifier(n_estimators=250, learning_rate=0.08, max_depth=7,
                                  min_child_weight=2, subsample=0.8, colsample_bytree=0.8,
                                  gamma=0.1, random_state=self.random_state, n_jobs=-1, eval_metric='logloss')),
            ('lgbm', LGBMClassifier(n_estimators=250, learning_rate=0.08, max_depth=7,
                                    num_leaves=50, min_child_samples=20, subsample=0.8,
                                    colsample_bytree=0.8, random_state=self.random_state, n_jobs=-1, verbose=-1)),
        ]
        meta_learner = LogisticRegression(max_iter=1000, C=0.5, class_weight=self.class_weight,
                                         random_state=self.random_state)
        return StackingClassifier(estimators=base_models, final_estimator=meta_learner,
                                  cv=5, stack_method='predict_proba', n_jobs=-1)

    def calibrate_model(self, model, X_val, y_val, method: str = 'isotonic'):
        logger.info(f"Calibrating model using {method} method...")
        calibrated = CalibratedClassifierCV(model, method=method, cv='prefit')
        calibrated.fit(X_val, y_val)
        logger.info("Model calibration complete")
        return calibrated

    def cross_validate(self, model, X, y, cv: int = 5) -> Dict[str, float]:
        logger.info(f"Performing {cv}-fold cross-validation...")
        cv_splitter = StratifiedKFold(n_splits=cv, shuffle=True, random_state=self.random_state)
        results = {
            'accuracy_mean': cross_val_score(model, X, y, cv=cv_splitter, scoring='accuracy', n_jobs=-1).mean(),
            'f1_mean': cross_val_score(model, X, y, cv=cv_splitter, scoring='f1', n_jobs=-1).mean(),
        }
        logger.info(f"CV Accuracy: {results['accuracy_mean']:.4f}, F1: {results['f1_mean']:.4f}")
        return results
