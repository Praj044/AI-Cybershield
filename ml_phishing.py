"""
ml_phishing.py
--------------
Offline ML-based phishing classifier using scikit-learn.
Pipeline: TF-IDF vectorizer → Logistic Regression classifier.

Trained on the bundled real-world dataset (Phishing_validation_emails.csv,
2 000 emails) on first call; model is cached in-process for the rest of the
session (~0 ms after first run).

Public API
----------
    classify_email_ml(text: str) -> dict
        Returns ml_score (0-100), ml_verdict (bool), ml_confidence,
        ml_label, ml_emoji, and top_features list.
"""

from __future__ import annotations

import csv
import os
import re
import threading
from typing import Optional

# ─── Dataset Path ─────────────────────────────────────────────────────────────
# Resolved relative to this file so it works from any working directory.
_MODULE_DIR  = os.path.dirname(os.path.abspath(__file__))
_DATASET_CSV = os.path.join(_MODULE_DIR, "dataset_extracted", "Phishing_validation_emails.csv")


def _load_dataset() -> tuple[list[str], list[int]]:
    """
    Loads the phishing email dataset from the bundled CSV file.

    CSV format:
        Email Text,Email Type
        "...",Phishing Email
        "...",Safe Email

    Returns
    -------
    texts  : list[str]  – raw email bodies
    labels : list[int]  – 1 = phishing, 0 = safe
    """
    texts:  list[str] = []
    labels: list[int] = []

    if not os.path.isfile(_DATASET_CSV):
        raise FileNotFoundError(
            f"Training dataset not found at:\n  {_DATASET_CSV}\n"
            "Please place Phishing_validation_emails.csv in the "
            "'dataset_extracted' folder inside the project directory."
        )

    with open(_DATASET_CSV, encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            text  = row.get("Email Text", "").strip()
            label = row.get("Email Type", "").strip()
            if not text or not label:
                continue
            if label == "Phishing Email":
                labels.append(1)
            elif label == "Safe Email":
                labels.append(0)
            else:
                # Skip unexpected label values
                continue
            texts.append(text)

    if not texts:
        raise ValueError("Dataset is empty or has an unexpected format.")

    phishing_count = sum(labels)
    safe_count     = len(labels) - phishing_count
    print(
        f"[ml_phishing] Dataset loaded: {len(texts)} emails "
        f"({phishing_count} phishing, {safe_count} safe)"
    )
    return texts, labels


# ─── Model Cache ──────────────────────────────────────────────────────────────
_model_lock    = threading.Lock()
_vectorizer    = None   # TfidfVectorizer
_classifier    = None   # LogisticRegression
_feature_names: list[str] = []


def _train_model() -> None:
    """Trains the TF-IDF + LogisticRegression pipeline and caches it globally."""
    global _vectorizer, _classifier, _feature_names

    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import FeatureUnion
    from sklearn.linear_model import LogisticRegression

    corpus, labels = _load_dataset()

    # Word n-gram vectoriser
    word_vec = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        max_features=6000,
        sublinear_tf=True,
        min_df=2,
        stop_words=None,
    )

    # Character n-gram vectoriser — captures spelling tricks & urgency patterns
    char_vec = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=4000,
        sublinear_tf=True,
        min_df=3,
    )

    # Combine both feature spaces
    combined = FeatureUnion(
        [("word", word_vec),
         ("char", char_vec)]
    )
    X = combined.fit_transform(corpus)

    # Lower C for stronger regularisation → better generalisation
    clf = LogisticRegression(
        C=1.0,
        max_iter=1000,
        solver="lbfgs",
        class_weight="balanced",
        random_state=42,
    )
    clf.fit(X, labels)

    # Store the combined vectoriser as _vectorizer
    _vectorizer    = combined
    _classifier    = clf
    # Feature names: word features first, then char features
    _feature_names = (
        word_vec.get_feature_names_out().tolist()
        + [f"char:{n}" for n in char_vec.get_feature_names_out()]
    )
    print("[ml_phishing] Model trained successfully (word + char n-grams).")


def _ensure_model() -> None:
    """Thread-safe lazy-loading: trains the model exactly once."""
    global _vectorizer, _classifier
    if _vectorizer is None:
        with _model_lock:
            if _vectorizer is None:   # double-checked locking
                _train_model()


def _top_phishing_features(x_vec, n: int = 5) -> list[str]:
    """
    Returns the top-n TF-IDF features in the given sample that most
    contributed to the phishing class (positive log-reg coefficient × TF-IDF weight).
    """
    import numpy as np

    coef          = _classifier.coef_[0]         # shape (n_features,)
    tfidf_weights = x_vec.toarray()[0]            # shape (n_features,)
    contribution  = coef * tfidf_weights

    # Top contributors for class=1 (phishing)
    top_idx = np.argsort(contribution)[::-1][:n]
    tokens  = [_feature_names[i] for i in top_idx if tfidf_weights[i] > 0]
    return tokens[:n]


# ─── Public API ───────────────────────────────────────────────────────────────

def classify_email_ml(text: str) -> dict:
    """
    Classifies email text as phishing or legitimate using a trained ML model.

    Args:
        text: Raw email content (any length).

    Returns:
        dict with keys:
            ml_score      (int 0-100)   — phishing probability × 100
            ml_verdict    (bool)        — True = phishing
            ml_confidence (str)         — "High" / "Medium" / "Low"
            ml_label      (str)         — "Phishing" / "Likely Safe" / etc.
            ml_emoji      (str)         — colour-coded emoji
            top_features  (list[str])   — words/bigrams that drove the prediction
    """
    if not text or not text.strip():
        return _empty_ml_result()

    _ensure_model()

    # Normalise: lowercase, collapse whitespace
    cleaned = re.sub(r"\s+", " ", text.lower().strip())
    X = _vectorizer.transform([cleaned])

    prob_phishing = float(_classifier.predict_proba(X)[0][1])
    ml_score      = min(100, int(prob_phishing * 100))
    ml_verdict    = prob_phishing >= 0.50

    # Confidence tiers
    if prob_phishing >= 0.75 or prob_phishing <= 0.25:
        ml_confidence = "High"
    elif prob_phishing >= 0.60 or prob_phishing <= 0.40:
        ml_confidence = "Medium"
    else:
        ml_confidence = "Low"

    # Emoji / label
    if ml_verdict:
        if ml_score >= 80:
            ml_emoji, ml_label = "🔴", "Phishing"
        elif ml_score >= 60:
            ml_emoji, ml_label = "🟠", "Likely Phishing"
        else:
            ml_emoji, ml_label = "🟡", "Suspicious"
    else:
        if ml_score <= 20:
            ml_emoji, ml_label = "✅", "Likely Safe"
        else:
            ml_emoji, ml_label = "🟢", "Probably Safe"

    top_features = _top_phishing_features(X, n=5)

    return {
        "ml_score":      ml_score,
        "ml_verdict":    ml_verdict,
        "ml_confidence": ml_confidence,
        "ml_label":      ml_label,
        "ml_emoji":      ml_emoji,
        "top_features":  top_features,
    }


def _empty_ml_result() -> dict:
    return {
        "ml_score":      0,
        "ml_verdict":    False,
        "ml_confidence": "N/A",
        "ml_label":      "No Input",
        "ml_emoji":      "⚪",
        "top_features":  [],
    }


# ─── Smoke test (run directly) ───────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from sklearn.model_selection import cross_val_score
    from sklearn.pipeline import Pipeline, FeatureUnion
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    import numpy as np

    # ── 1. Quick classification smoke test ───────────────────────────────────────────────
    print("\n=== Smoke Test: classify_email_ml ===")
    tests = [
        # Clear phishing: financial urgency, account threats, prize claims
        ("PHISHING", "Your account has been suspended click here immediately to verify or lose access within 24 hours"),
        ("PHISHING", "Congratulations you have won a 1000 dollar gift card claim your prize now before it expires"),
        ("PHISHING", "Dear user your PayPal account is limited confirm your information now at secure-paypal-verify.com"),
        ("PHISHING", "URGENT your Microsoft account password will expire click here to update your credentials now"),
        ("PHISHING", "IRS notification you owe back taxes legal action will be taken within 48 hours if unpaid"),
        # Clear safe: internal / personal / informational with no account urgency
        ("SAFE",     "Hi team please find the quarterly report attached let me know if you have any questions thanks"),
        ("SAFE",     "Just a reminder the team lunch is on Thursday at noon in the main conference room see you there"),
        ("SAFE",     "Good morning I wanted to follow up on our meeting yesterday regarding the project timeline update"),
        ("SAFE",     "Hey hope you are doing well just wanted to catch up and see how the new job is going for you"),
        ("SAFE",     "The community board meeting has been moved to next Thursday please update your calendars accordingly"),
    ]
    passed = 0
    for expected, email in tests:
        result  = classify_email_ml(email)
        correct = result["ml_verdict"] == (expected == "PHISHING")
        if correct:
            passed += 1
        status  = "PASS" if correct else "FAIL"
        print(
            f"[{status}] [{expected:8s}] score={result['ml_score']:3d}  "
            f"label={result['ml_label']:<18s}  features={result['top_features'][:3]}"
        )
    print(f"\nSmoke test: {passed}/{len(tests)} passed")

    # 2. Cross-validation accuracy on full dataset ───────────────────────────────────
    print("\n=== Cross-Validation Accuracy (5-fold) ===")
    texts, labels = _load_dataset()
    pipe = Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                     max_features=6000, sublinear_tf=True, min_df=2)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                                     max_features=4000, sublinear_tf=True, min_df=3)),
        ])),
        ("clf", LogisticRegression(C=1.0, max_iter=1000, solver="lbfgs",
                                    class_weight="balanced", random_state=42)),
    ])
    scores = cross_val_score(pipe, texts, labels, cv=5, scoring="accuracy")
    print(f"Accuracy per fold : {[f'{s:.1%}' for s in scores]}")
    print(f"Mean accuracy     : {scores.mean():.1%}  +/-{scores.std():.1%}")
