"""Quick verification script for the retrained phishing ML model."""
import csv
import sys

# ── 1. Load dataset and print stats ──────────────────────────────────────────
dataset_path = "dataset_extracted/Phishing_validation_emails.csv"
texts, labels = [], []
with open(dataset_path, encoding="utf-8", errors="replace", newline="") as f:
    for row in csv.DictReader(f):
        t = row.get("Email Text", "").strip()
        l = row.get("Email Type", "").strip()
        if not t or l not in ("Phishing Email", "Safe Email"):
            continue
        texts.append(t)
        labels.append(1 if l == "Phishing Email" else 0)

phishing_count = sum(labels)
safe_count     = len(labels) - phishing_count
print(f"Dataset loaded: {len(texts)} total  |  {phishing_count} phishing  |  {safe_count} safe")

# ── 2. 5-Fold Cross-Validation ────────────────────────────────────────────────
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
import numpy as np

pipe = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=8000,
                               sublinear_tf=True, min_df=2)),
    ("clf",   LogisticRegression(C=5.0, max_iter=1000, solver="lbfgs",
                                  class_weight="balanced", random_state=42)),
])
scores = cross_val_score(pipe, texts, labels, cv=5, scoring="accuracy")
print(f"\n5-Fold CV Accuracy per fold : {[round(s, 4) for s in scores]}")
print(f"Mean accuracy               : {scores.mean():.4f}  (Std: {scores.std():.4f})")

# ── 3. Smoke test against classify_email_ml() ─────────────────────────────────
from ml_phishing import classify_email_ml

tests = [
    ("PHISHING", "Your account has been suspended click here immediately to verify or lose access"),
    ("SAFE",     "Hi team please find the quarterly report attached let me know if you have questions"),
    ("PHISHING", "Congratulations you have won a 1000 dollar gift card claim your prize now before it expires"),
    ("SAFE",     "Just a reminder the team lunch is on Thursday at noon in the main conference room"),
    ("PHISHING", "Dear user your PayPal account is limited confirm your information now at secure site"),
    ("SAFE",     "Your flight to New York on March 20th is confirmed please check in online 24 hours before"),
    ("PHISHING", "URGENT your Microsoft account password will expire click here to update your credentials"),
    ("SAFE",     "Good morning I wanted to follow up on our meeting yesterday regarding the project timeline"),
]

print("\n=== Smoke Test ===")
all_correct = True
for expected, email in tests:
    result  = classify_email_ml(email)
    correct = result["ml_verdict"] == (expected == "PHISHING")
    if not correct:
        all_correct = False
    mark = "PASS" if correct else "FAIL"
    feats = ", ".join(result["top_features"][:3]) if result["top_features"] else "—"
    print(
        f"[{mark}] [{expected:8s}]  score={result['ml_score']:3d}  "
        f"label={result['ml_label']:<18s}  top_features=[{feats}]"
    )

print()
if all_correct:
    print("All smoke tests PASSED! Model is working correctly.")
else:
    print("Some smoke tests FAILED — check above for details.")
    sys.exit(1)
