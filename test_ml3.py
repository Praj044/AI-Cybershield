import csv, json, sys, os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

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
safe_count = len(labels) - phishing_count

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
import numpy as np

pipe = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1,2), max_features=8000, sublinear_tf=True, min_df=2)),
    ("clf",   LogisticRegression(C=5.0, max_iter=1000, solver="lbfgs", class_weight="balanced", random_state=42)),
])
scores = cross_val_score(pipe, texts, labels, cv=5, scoring="accuracy")

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

smoke_results = []
for expected, email in tests:
    result = classify_email_ml(email)
    correct = result["ml_verdict"] == (expected == "PHISHING")
    smoke_results.append({
        "expected": expected,
        "correct": correct,
        "score": result["ml_score"],
        "label": result["ml_label"],
        "top_feats": result["top_features"][:3],
        "email_snippet": email[:60]
    })

output = {
    "dataset": {"total": len(texts), "phishing": phishing_count, "safe": safe_count},
    "cv_accuracy": {"per_fold": [round(s,4) for s in scores], "mean": round(scores.mean(),4), "std": round(scores.std(),4)},
    "smoke_tests": smoke_results,
    "all_passed": all(r["correct"] for r in smoke_results)
}

with open("ml_test_results.json", "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2)

print("Done. Results in ml_test_results.json")
