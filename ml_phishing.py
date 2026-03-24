"""
ml_phishing.py
--------------
Robust ML-based phishing classifier.

✔ Uses dataset if available
✔ Falls back to small built-in dataset if missing
✔ Saves trained model (model.pkl)
✔ Loads model instantly on next runs
"""

from __future__ import annotations

import csv
import os
import re
import threading
import joblib
from typing import Optional

# ─── Paths ─────────────────────────────────────────────────────────────
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_DATASET_CSV = os.path.join(_MODULE_DIR, "dataset_extracted", "Phishing_validation_emails.csv")
_MODEL_FILE = os.path.join(_MODULE_DIR, "model.pkl")

# ─── Model Cache ───────────────────────────────────────────────────────
_model_lock = threading.Lock()
_vectorizer = None
_classifier = None
_feature_names: list[str] = []


# ─── Dataset Loader (SAFE) ─────────────────────────────────────────────
def _load_dataset():
    texts = []
    labels = []

    if not os.path.isfile(_DATASET_CSV):
        print("⚠️ Dataset not found → using fallback dataset")

        texts = [
            "Click here to verify your bank account immediately",
            "Your account has been suspended, act now",
            "Win a free iPhone now!!!",
            "Update your password immediately",
            "Meeting scheduled for tomorrow",
            "Project report attached",
        ]
        labels = [1, 1, 1, 1, 0, 0]
        return texts, labels

    with open(_DATASET_CSV, encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            text = row.get("Email Text", "").strip()
            label = row.get("Email Type", "").strip()

            if not text or not label:
                continue

            if label == "Phishing Email":
                labels.append(1)
            elif label == "Safe Email":
                labels.append(0)
            else:
                continue

            texts.append(text)

    return texts, labels


# ─── Train Model ───────────────────────────────────────────────────────
def _train_model():
    global _vectorizer, _classifier, _feature_names

    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import FeatureUnion
    from sklearn.linear_model import LogisticRegression

    texts, labels = _load_dataset()

    word_vec = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        max_features=6000,
        sublinear_tf=True,
        min_df=1,
    )

    char_vec = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=4000,
        sublinear_tf=True,
        min_df=1,
    )

    combined = FeatureUnion([
        ("word", word_vec),
        ("char", char_vec),
    ])

    X = combined.fit_transform(texts)

    clf = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42,
    )

    clf.fit(X, labels)

    _vectorizer = combined
    _classifier = clf

    _feature_names = (
        word_vec.get_feature_names_out().tolist()
        + [f"char:{f}" for f in char_vec.get_feature_names_out()]
    )

    print("✅ Model trained successfully")


# ─── Ensure Model (LOAD or TRAIN) ──────────────────────────────────────
def _ensure_model():
    global _vectorizer, _classifier, _feature_names

    if _vectorizer is not None:
        return

    with _model_lock:
        if _vectorizer is not None:
            return

        if os.path.exists(_MODEL_FILE):
            print("⚡ Loading saved model...")
            _vectorizer, _classifier, _feature_names = joblib.load(_MODEL_FILE)
        else:
            print("🚀 Training model...")
            _train_model()
            joblib.dump((_vectorizer, _classifier, _feature_names), _MODEL_FILE)


# ─── Top Features ──────────────────────────────────────────────────────
def _top_phishing_features(x_vec, n=5):
    import numpy as np

    coef = _classifier.coef_[0]
    weights = x_vec.toarray()[0]
    contribution = coef * weights

    top_idx = np.argsort(contribution)[::-1][:n]
    return [_feature_names[i] for i in top_idx if weights[i] > 0][:n]


# ─── Public API ────────────────────────────────────────────────────────
def classify_email_ml(text: str):
    if not text or not text.strip():
        return _empty_result()

    _ensure_model()

    cleaned = re.sub(r"\s+", " ", text.lower().strip())
    X = _vectorizer.transform([cleaned])

    prob = float(_classifier.predict_proba(X)[0][1])
    score = int(prob * 100)

    verdict = prob >= 0.5

    # Confidence
    if prob >= 0.75 or prob <= 0.25:
        confidence = "High"
    elif prob >= 0.6 or prob <= 0.4:
        confidence = "Medium"
    else:
        confidence = "Low"

    # Labels
    if verdict:
        if score >= 80:
            label, emoji = "Phishing", "🔴"
        elif score >= 60:
            label, emoji = "Likely Phishing", "🟠"
        else:
            label, emoji = "Suspicious", "🟡"
    else:
        if score <= 20:
            label, emoji = "Likely Safe", "✅"
        else:
            label, emoji = "Probably Safe", "🟢"

    return {
        "ml_score": score,
        "ml_verdict": verdict,
        "ml_confidence": confidence,
        "ml_label": label,
        "ml_emoji": emoji,
        "top_features": _top_phishing_features(X),
    }


def _empty_result():
    return {
        "ml_score": 0,
        "ml_verdict": False,
        "ml_confidence": "N/A",
        "ml_label": "No Input",
        "ml_emoji": "⚪",
        "top_features": [],
    }