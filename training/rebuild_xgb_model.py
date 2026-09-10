"""
Rebuild xgb_email_threat_model.pkl — the committed pickle is corrupt
("XGBoostError: input stream corrupted"), which made the ML ensemble return
'unknown' for every scan. This script retrains the XGBoost leg of the ensemble
with the same hyperparameters and dataset pipeline as the Colab training
notebook (training/SIH26106_Email_Threat_Detection_Training.ipynb), but cleans
text with the backend's own _clean_text/_extract_manual_features so training
features exactly match inference features.

Usage:
    python training/rebuild_xgb_model.py
"""

import csv
import json
import os
import re
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from scipy.sparse import hstack, csr_matrix
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).parent.parent
DATASET_DIR = PROJECT_ROOT / "training" / "datasets"
MODELS_DIR = PROJECT_ROOT / "backend" / "ml" / "models"

# Same cleaning/features the backend applies at inference time
sys.path.insert(0, str(PROJECT_ROOT))
from backend.services.ml_predictor import _clean_text, _extract_manual_features, MANUAL_FEATURE_COLS  # noqa: E402


def to_binary(series, phishing_values):
    phishing_values = {str(v).strip().lower() for v in phishing_values}
    return series.apply(lambda x: 1 if str(x).strip().lower() in phishing_values else 0)


def first_text_col(d, fname):
    candidates = [c for c in d.columns if any(k in c.lower() for k in ['text', 'body', 'email', 'content', 'message'])]
    if not candidates:
        raise ValueError(f'{fname}: no text-like column found in {list(d.columns)}')
    return candidates[0]


def load_all_datasets():
    frames = []

    # 1. Phishing_Email.csv
    df1 = pd.read_csv(DATASET_DIR / 'Phishing_Email.csv')
    df1 = df1.rename(columns={'Email Text': 'text', 'Email Type': 'raw_label'})
    df1 = df1[['text', 'raw_label']].dropna(subset=['text'])
    df1['label'] = to_binary(df1['raw_label'], phishing_values=['phishing email', 'phishing'])
    df1['source'] = 'phishing_email_main'
    frames.append(df1[['text', 'label', 'source']])

    # 2. phishing_legitimate_emails.csv
    df2 = pd.read_csv(DATASET_DIR / 'phishing_legitimate_emails.csv')
    df2 = df2.rename(columns={'Message': 'text', 'Category': 'raw_label'})
    df2 = df2[['text', 'raw_label']].dropna(subset=['text'])
    df2['label'] = to_binary(df2['raw_label'], phishing_values=['spam', 'phishing', 'phishing email', '1'])
    df2['source'] = 'phishing_legit_classifier'
    frames.append(df2[['text', 'label', 'source']])

    # 3. human_legit.csv / human_phishing.csv
    df_hl = pd.read_csv(DATASET_DIR / 'human_legit.csv')
    df_hp = pd.read_csv(DATASET_DIR / 'human_phishing.csv')
    hl_col = first_text_col(df_hl, 'human_legit.csv')
    hp_col = first_text_col(df_hp, 'human_phishing.csv')
    df_human = pd.DataFrame({
        'text': pd.concat([df_hl[hl_col], df_hp[hp_col]], ignore_index=True),
        'label': pd.concat([pd.Series([0] * len(df_hl)), pd.Series([1] * len(df_hp))], ignore_index=True),
        'source': 'human_generated',
    }).dropna(subset=['text'])
    frames.append(df_human)

    # 4. llm_legit.csv / llm_phishing.csv
    df_ll = pd.read_csv(DATASET_DIR / 'llm_legit.csv', engine='python', on_bad_lines='warn')
    lp_rows = []
    with open(DATASET_DIR / 'llm_phishing.csv', 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if len(row) >= 2:
                lp_rows.append({'text': ','.join(row[:-1]), 'label': int(row[-1].strip())})
    df_lp = pd.DataFrame(lp_rows)
    ll_col = first_text_col(df_ll, 'llm_legit.csv')
    lp_col = first_text_col(df_lp, 'llm_phishing.csv')
    df_llm = pd.DataFrame({
        'text': pd.concat([df_ll[ll_col], df_lp[lp_col]], ignore_index=True),
        'label': pd.concat([pd.Series([0] * len(df_ll)), pd.Series([1] * len(df_lp))], ignore_index=True),
        'source': 'llm_generated',
    }).dropna(subset=['text'])
    frames.append(df_llm)

    # 5. mail_data.csv
    df5 = pd.read_csv(DATASET_DIR / 'mail_data.csv')
    text_candidates = [c for c in df5.columns if any(k in c.lower() for k in ['text', 'message', 'email', 'body'])]
    label_candidates = [c for c in df5.columns if any(k in c.lower() for k in ['label', 'class', 'category'])]
    if not text_candidates or not label_candidates:
        raise ValueError(f'mail_data.csv: columns {list(df5.columns)} not recognized')
    df5 = df5.rename(columns={text_candidates[0]: 'text', label_candidates[0]: 'raw_label'}).dropna(subset=['text'])
    df5['label'] = to_binary(df5['raw_label'], phishing_values=['spam', '1', 'phishing'])
    df5['source'] = 'spam_dataset'
    frames.append(df5[['text', 'label', 'source']])

    df = pd.concat(frames, ignore_index=True)
    df = df.dropna(subset=['text'])
    df['text'] = df['text'].astype(str)
    df = df[df['text'].str.len() > 10].reset_index(drop=True)
    return df


def main():
    t0 = time.time()
    print('Loading datasets ...', flush=True)
    df = load_all_datasets()
    print(f'  {len(df):,} rows | phishing={df.label.sum():,} legit={(df.label==0).sum():,}', flush=True)

    print('Cleaning text + engineering features (backend-consistent) ...', flush=True)
    df['text_clean'] = df['text'].apply(_clean_text)
    feats = pd.DataFrame([_extract_manual_features(t) for t in df['text']])
    df = pd.concat([df.reset_index(drop=True), feats], axis=1)

    # Exact same split as the notebook
    df_train, df_temp = train_test_split(df, test_size=0.30, random_state=42, stratify=df['label'])
    df_val, df_test = train_test_split(df_temp, test_size=0.50, random_state=42, stratify=df_temp['label'])

    # Reuse the fitted TF-IDF vectorizer already shipped with the backend
    tfidf = joblib.load(MODELS_DIR / 'tfidf_vectorizer.pkl')
    feat_cols = json.loads((MODELS_DIR / 'feature_cols.json').read_text()) or MANUAL_FEATURE_COLS

    X_train_tfidf = tfidf.transform(df_train['text_clean'])
    X_val_tfidf = tfidf.transform(df_val['text_clean'])
    X_test_tfidf = tfidf.transform(df_test['text_clean'])

    X_train_hand = csr_matrix(df_train[feat_cols].fillna(0).values)
    X_val_hand = csr_matrix(df_val[feat_cols].fillna(0).values)
    X_test_hand = csr_matrix(df_test[feat_cols].fillna(0).values)

    X_train = hstack([X_train_tfidf, X_train_hand]).tocsr()
    X_val = hstack([X_val_tfidf, X_val_hand]).tocsr()
    X_test = hstack([X_test_tfidf, X_test_hand]).tocsr()

    y_train, y_val, y_test = df_train['label'].values, df_val['label'].values, df_test['label'].values
    print(f'  X_train {X_train.shape} | X_val {X_val.shape} | X_test {X_test.shape}', flush=True)

    scale_pos = (y_train == 0).sum() / (y_train == 1).sum()
    model = xgb.XGBClassifier(
        n_estimators=400,
        max_depth=7,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos,
        eval_metric='logloss',
        tree_method='hist',
        random_state=42,
        n_jobs=4,  # bounded — n_jobs=-1 can deadlock on Windows
    )
    print('Training XGBoost ...', flush=True)
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)

    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    print(f'  Test  — acc={accuracy_score(y_test, y_pred):.3f} '
          f'prec={precision_score(y_test, y_pred, zero_division=0):.3f} '
          f'rec={recall_score(y_test, y_pred, zero_division=0):.3f} '
          f'f1={f1_score(y_test, y_pred, zero_division=0):.3f} '
          f'auc={roc_auc_score(y_test, y_prob):.4f}')

    out = MODELS_DIR / 'xgb_email_threat_model.pkl'
    joblib.dump(model, out)
    print(f'  Saved -> {out} ({out.stat().st_size:,} bytes) in {time.time()-t0:.0f}s')

    # Sanity: does the backend predictor load it and return real predictions?
    from backend.services.ml_predictor import get_ml_predictor
    p = get_ml_predictor()
    print('  backend email model loaded:', p.is_email_model_loaded())
    for sample in [
        'URGENT: Your account has been locked. Click http://evil.xyz/verify now to restore access.',
        'Hi team, attached is the Q3 report we discussed in the standup. Thanks!',
    ]:
        print('  predict ->', p.predict_email(sample))


if __name__ == '__main__':
    main()