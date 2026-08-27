"""
Data Loading and Preprocessing Module
Handles loading from multiple Kaggle datasets with intelligent preprocessing
"""

import os
import pandas as pd
import numpy as np
from typing import Tuple, List
from collections import Counter
import logging
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)


class DataLoader:
    """Efficient data loader for email and URL datasets"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.email_datasets = self._get_email_dataset_paths()
        self.url_datasets = self._get_url_dataset_paths()

    def _get_email_dataset_paths(self) -> List[str]:
        base = self.data_dir
        return [
            os.path.join(base, "Email Phishing Legitimate classifier", "phishing_legitimate_emails.csv"),
            os.path.join(base, "Spam Email Dataset", "mail_data.csv"),
            os.path.join(base, "Human-LLM generated phishing-legitimate emails", "human-generated", "legit.csv"),
            os.path.join(base, "Human-LLM generated phishing-legitimate emails", "human-generated", "phishing.csv"),
            os.path.join(base, "Human-LLM generated phishing-legitimate emails", "llm-generated", "legit.csv"),
            os.path.join(base, "Human-LLM generated phishing-legitimate emails", "llm-generated", "phishing.csv"),
        ]

    def _get_url_dataset_paths(self) -> List[str]:
        base = self.data_dir
        return [
            os.path.join(base, "Binary Dataset of Phishing and Legitimate URLs", "Dataset.csv"),
            os.path.join(base, "Legitimate and phishing website dataset", "dataset.csv"),
            os.path.join(base, "Legitimate-URLs", "1.Benign_list_big_final.csv"),
            os.path.join(base, "legitimate_urls_computed", "legitimate (3).csv"),
        ]

    def load_email_data(self, balance: bool = True, min_length: int = 10) -> Tuple[List[str], List[str]]:
        logger.info("Loading email datasets...")
        emails, labels = [], []

        for file_path in self.email_datasets:
            try:
                if not os.path.exists(file_path):
                    logger.warning(f"File not found: {file_path}")
                    continue

                logger.info(f"Loading: {os.path.basename(file_path)}")
                df = self._read_csv_robust(file_path)

                is_phishing = "phishing" in file_path.lower() or "spam" in file_path.lower()
                text_col, label_col = self._find_columns(df)

                if text_col:
                    email_texts = df[text_col].astype(str).tolist()

                    if label_col:
                        file_labels = self._normalize_labels(df[label_col].tolist())
                    else:
                        file_labels = ['phishing' if is_phishing else 'legitimate'] * len(email_texts)

                    for text, label in zip(email_texts, file_labels):
                        if len(text) >= min_length:
                            emails.append(text)
                            labels.append(label)

                    logger.info(f"  Loaded {len(email_texts)} emails")
            except Exception as e:
                logger.error(f"Error loading {file_path}: {str(e)}")
                continue

        logger.info(f"Total emails loaded: {len(emails)}")
        emails, labels = self._remove_duplicates(emails, labels)
        logger.info(f"After deduplication: {len(emails)}")

        if balance:
            emails, labels = self._balance_classes(emails, labels)
            logger.info(f"After balancing: {len(emails)}")

        logger.info(f"Class distribution: {dict(Counter(labels))}")
        return emails, labels

    def load_url_data(self, balance: bool = True, min_length: int = 15) -> Tuple[List[str], List[str]]:
        logger.info("Loading URL datasets...")
        urls, labels = [], []

        for file_path in self.url_datasets:
            try:
                if not os.path.exists(file_path):
                    logger.warning(f"File not found: {file_path}")
                    continue

                logger.info(f"Loading: {os.path.basename(file_path)}")
                df = self._read_csv_robust(file_path)

                url_col = self._find_url_column(df)
                label_col = self._find_label_column(df)

                if url_col:
                    file_urls = df[url_col].astype(str).tolist()

                    if label_col:
                        file_labels = self._normalize_labels(df[label_col].tolist())
                    else:
                        is_phishing = 'phish' in file_path.lower() or 'malicious' in file_path.lower()
                        file_labels = ['phishing' if is_phishing else 'legitimate'] * len(file_urls)

                    for url, label in zip(file_urls, file_labels):
                        if self._is_valid_url(url) and len(url) >= min_length:
                            urls.append(url)
                            labels.append(label)

                    logger.info(f"  Loaded {len(file_urls)} URLs")
            except Exception as e:
                logger.error(f"Error loading {file_path}: {str(e)}")
                continue

        logger.info(f"Total URLs loaded: {len(urls)}")
        urls, labels = self._remove_duplicates(urls, labels)
        logger.info(f"After deduplication: {len(urls)}")

        if balance:
            urls, labels = self._balance_classes(urls, labels)
            logger.info(f"After balancing: {len(urls)}")

        logger.info(f"Class distribution: {dict(Counter(labels))}")
        return urls, labels

    def split_data(self, texts: List[str], labels: List[str],
                   test_size: float = 0.15, val_size: float = 0.10) -> dict:
        X_train_val, X_test, y_train_val, y_test = train_test_split(
            texts, labels, test_size=test_size, random_state=42, stratify=labels
        )
        relative_val_size = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_train_val, y_train_val, test_size=relative_val_size, random_state=42, stratify=y_train_val
        )
        return {
            'X_train': X_train, 'X_val': X_val, 'X_test': X_test,
            'y_train': y_train, 'y_val': y_val, 'y_test': y_test
        }

    # --- Internal helpers ---

    def _read_csv_robust(self, file_path: str) -> pd.DataFrame:
        for encoding in ['utf-8', 'latin1', 'ISO-8859-1', 'cp1252']:
            try:
                return pd.read_csv(file_path, encoding=encoding, on_bad_lines='skip')
            except Exception:
                continue
        raise ValueError(f"Could not read {file_path} with any encoding")

    def _find_columns(self, df: pd.DataFrame):
        text_col = None
        label_col = None

        text_candidates = ['text', 'email', 'message', 'content', 'body', 'Email Text', 'Email', 'Message']
        for col in df.columns:
            if col.lower().strip() in [c.lower() for c in text_candidates]:
                text_col = col
                break
        if not text_col:
            for col in df.columns:
                sample = df[col].dropna().astype(str).head(5)
                avg_len = sample.str.len().mean()
                if avg_len > 50:
                    text_col = col
                    break

        label_candidates = ['label', 'class', 'target', 'prediction', 'Category', 'Label']
        for col in df.columns:
            if col.lower().strip() in [c.lower() for c in label_candidates]:
                label_col = col
                break

        return text_col, label_col

    def _find_url_column(self, df: pd.DataFrame) -> str:
        for col in df.columns:
            if col.lower().strip() in ['url', 'urls', 'domain', 'link', 'website']:
                return col
        for col in df.columns:
            sample = df[col].dropna().astype(str).head(5)
            if sample.str.contains(r'https?://', regex=True).any():
                return col
        return df.columns[0] if len(df.columns) > 0 else None

    def _find_label_column(self, df: pd.DataFrame):
        for col in df.columns:
            if col.lower().strip() in ['label', 'class', 'target', 'result', 'status', 'Category', 'Label']:
                return col
        return None

    def _normalize_labels(self, labels) -> list:
        normalized = []
        for label in labels:
            label_str = str(label).lower().strip()
            if label_str in ['1', 'phishing', 'spam', 'malicious', 'true', 'yes', 'bad']:
                normalized.append('phishing')
            else:
                normalized.append('legitimate')
        return normalized

    def _remove_duplicates(self, texts: list, labels: list):
        seen = set()
        unique_texts, unique_labels = [], []
        for text, label in zip(texts, labels):
            text_hash = hash(text.strip().lower())
            if text_hash not in seen:
                seen.add(text_hash)
                unique_texts.append(text)
                unique_labels.append(label)
        return unique_texts, unique_labels

    def _balance_classes(self, texts: list, labels: list):
        from collections import Counter
        counts = Counter(labels)
        min_count = min(counts.values())

        balanced_texts, balanced_labels = [], []
        class_indices = {}
        for i, label in enumerate(labels):
            if label not in class_indices:
                class_indices[label] = []
            class_indices[label].append(i)

        for label, indices in class_indices.items():
            selected = indices[:min_count]
            for idx in selected:
                balanced_texts.append(texts[idx])
                balanced_labels.append(labels[idx])

        return balanced_texts, balanced_labels

    def _is_valid_url(self, url: str) -> bool:
        return url.startswith(('http://', 'https://', 'www.')) or '.' in url
