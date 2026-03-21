"""
score_calculator.py
--------------------
Aggregates results from all security modules and computes a
holistic security score from 0-100.

Scoring Formula:
  Baseline: 100 points
  Deductions:
    - Password weakness: 0 (score 4) to 40 (score 0)
    - Phishing detection: 50 (if phishing), 20 (if medium confidence)
    - URL risk: 30 (high), 15 (medium), 0 (low) — capped at 40 total

  Final Score = max(0, 100 - sum(all deductions))
"""


SCORE_BANDS = [
    (90, 100, "Excellent", "🛡️", "#00c853"),
    (70, 89,  "Good",      "✅", "#69f0ae"),
    (50, 69,  "Fair",      "🟡", "#ffd600"),
    (30, 49,  "Poor",      "🟠", "#ff6d00"),
    (0,  29,  "Critical",  "🔴", "#d50000"),
]


def calculate_security_score(
    password_deduction: int = 0,
    phishing_deduction: int = 0,
    url_deduction: int = 0,
) -> dict:
    """
    Computes the final security score.

    Args:
        password_deduction (int): Points deducted for weak password (0-40).
        phishing_deduction (int): Points deducted for phishing email (0-50).
        url_deduction (int): Points deducted for risky URLs (0-40).

    Returns:
        dict: {
            "score": int (0-100),
            "grade": str,
            "emoji": str,
            "color": str,
            "breakdown": dict,
        }
    """
    total_deduction = password_deduction + phishing_deduction + url_deduction
    score = max(0, 100 - total_deduction)

    grade, emoji, color = _get_band(score)

    return {
        "score": score,
        "grade": grade,
        "emoji": emoji,
        "color": color,
        "breakdown": {
            "password_deduction": password_deduction,
            "phishing_deduction": phishing_deduction,
            "url_deduction": url_deduction,
            "total_deduction": total_deduction,
        },
    }


def _get_band(score: int):
    """Returns (grade, emoji, color) for the given score."""
    for low, high, grade, emoji, color in SCORE_BANDS:
        if low <= score <= high:
            return grade, emoji, color
    return "Unknown", "❓", "#9e9e9e"


def get_score_summary(score_result: dict) -> str:
    """Returns a one-line human-readable summary of the score."""
    score = score_result["score"]
    grade = score_result["grade"]
    emoji = score_result["emoji"]
    breakdown = score_result["breakdown"]

    parts = []
    if breakdown["password_deduction"] > 0:
        parts.append(f"-{breakdown['password_deduction']} pwd")
    if breakdown["phishing_deduction"] > 0:
        parts.append(f"-{breakdown['phishing_deduction']} phishing")
    if breakdown["url_deduction"] > 0:
        parts.append(f"-{breakdown['url_deduction']} links")

    detail = f"({', '.join(parts)})" if parts else "(no deductions)"
    return f"{emoji} Security Score: {score}/100 — {grade} {detail}"
