"""
phishing_nlp.py
----------------
Advanced NLP-based phishing pre-scorer.
Runs entirely OFFLINE — no API calls needed.
Produces a phishing probability score (0–100) based on:
  • Urgency language detection
  • Authority impersonation
  • Fear / threat tactics
  • Reward / prize baiting
  • Suspicious call-to-action phrases
  • Sender spoofing indicators
  • Grammatical anomaly proxies

This score supplements the AI verdict from ai_engine.py.
"""

import re

# ─── Keyword Categories (weighted) ────────────────────────────────────────────

URGENCY_PATTERNS = {
    "phrases": [
        "act now", "immediately", "urgent", "right away", "asap",
        "limited time", "expires", "last chance", "final notice",
        "within 24 hours", "within 48 hours", "do not delay",
        "time sensitive", "respond immediately", "action required",
    ],
    "weight": 12,
}

AUTHORITY_PATTERNS = {
    "phrases": [
        "your bank", "internal revenue", "irs", "fbi", "police",
        "government", "legal department", "compliance team", "microsoft",
        "apple", "google", "amazon", "paypal", "netflix", "facebook",
        "support team", "account department", "security team",
        "official notice", "official notification",
    ],
    "weight": 8,
}

FEAR_PATTERNS = {
    "phrases": [
        "suspended", "locked", "compromised", "unauthorized access",
        "detected unusual", "blocked", "flagged", "limited access",
        "will be terminated", "legal action", "prosecuted", "arrested",
        "account closed", "access revoked", "deactivated",
    ],
    "weight": 15,
}

REWARD_PATTERNS = {
    "phrases": [
        "you have won", "congratulations", "selected", "winner",
        "free gift", "claim your", "prize", "lottery", "reward",
        "bonus", "$1000", "$500", "gift card", "voucher",
        "unclaimed funds", "inheritance",
    ],
    "weight": 14,
}

CTA_PATTERNS = {
    "phrases": [
        "click here", "click the link", "click below", "open the attachment",
        "download the file", "verify your", "confirm your",
        "update your information", "provide your", "enter your",
        "submit your", "log in now", "sign in here",
    ],
    "weight": 10,
}

SPOOFING_PATTERNS = {
    # Regex patterns for spoofed email / domain indicators
    "regexes": [
        r"no.?reply@",
        r"support@.*\.xyz",
        r"security@.*\.tk",
        r"admin@[a-z0-9]+-[a-z0-9]+\.",
        r"from:.*<.*@(?!gmail|yahoo|outlook|hotmail)[a-z0-9-]+\.(xyz|tk|ml|ga|cf|top)>",
        r"\bdo not reply\b",
    ],
    "weight": 18,
}

GRAMMAR_ANOMALY_PATTERNS = {
    # Quick proxies for poor grammar (common in phishing)
    "phrases": [
        "kindly do the needful",
        "dear valued customer",
        "dear user",
        "dear account holder",
        "we has detected",
        "your account has been temporary",
        "revert back to us",
        "do the necessary",
    ],
    "weight": 7,
}


# ─── Scorer ───────────────────────────────────────────────────────────────────

def score_phishing_nlp(text: str) -> dict:
    """
    Analyzes email text for phishing indicators using NLP heuristics.

    Args:
        text (str): Raw email content.

    Returns:
        dict: {
            "nlp_score": int 0-100,
            "risk_label": str,
            "risk_emoji": str,
            "category_hits": dict,   # which categories triggered
            "top_triggers": list,    # top matched phrases/patterns
        }
    """
    if not text or not text.strip():
        return _empty_nlp_result()

    text_lower = text.lower()
    total_score = 0
    category_hits = {}
    top_triggers = []

    # ── Phrase-based categories ──
    for cat_name, cat in [
        ("Urgency",       URGENCY_PATTERNS),
        ("Authority",     AUTHORITY_PATTERNS),
        ("Fear/Threat",   FEAR_PATTERNS),
        ("Reward Bait",   REWARD_PATTERNS),
        ("Call-to-Action",CTA_PATTERNS),
        ("Grammar",       GRAMMAR_ANOMALY_PATTERNS),
    ]:
        hits = [p for p in cat["phrases"] if p in text_lower]
        if hits:
            contribution = min(cat["weight"] * len(hits), cat["weight"] * 2)
            total_score += contribution
            category_hits[cat_name] = hits[:3]  # max 3 examples
            top_triggers.extend(hits[:2])

    # ── Regex-based spoofing checks ──
    spoof_hits = []
    for pattern in SPOOFING_PATTERNS["regexes"]:
        match = re.search(pattern, text_lower, re.IGNORECASE)
        if match:
            spoof_hits.append(match.group())
    if spoof_hits:
        total_score += SPOOFING_PATTERNS["weight"] * min(len(spoof_hits), 2)
        category_hits["Sender Spoofing"] = spoof_hits[:2]
        top_triggers.extend(spoof_hits[:1])

    # ── Normalize to 0–100 ──
    max_possible = sum([
        URGENCY_PATTERNS["weight"] * 2,
        AUTHORITY_PATTERNS["weight"] * 2,
        FEAR_PATTERNS["weight"] * 2,
        REWARD_PATTERNS["weight"] * 2,
        CTA_PATTERNS["weight"] * 2,
        GRAMMAR_ANOMALY_PATTERNS["weight"] * 2,
        SPOOFING_PATTERNS["weight"] * 2,
    ])
    nlp_score = min(100, int((total_score / max_possible) * 100))

    # ── Risk label ──
    if nlp_score >= 70:
        risk_label, risk_emoji = "Very High Risk", "🔴"
    elif nlp_score >= 45:
        risk_label, risk_emoji = "High Risk", "🟠"
    elif nlp_score >= 25:
        risk_label, risk_emoji = "Moderate Risk", "🟡"
    elif nlp_score >= 10:
        risk_label, risk_emoji = "Low Risk", "🟢"
    else:
        risk_label, risk_emoji = "Minimal Risk", "✅"

    return {
        "nlp_score": nlp_score,
        "risk_label": risk_label,
        "risk_emoji": risk_emoji,
        "category_hits": category_hits,
        "top_triggers": list(set(top_triggers))[:6],
    }


def _empty_nlp_result() -> dict:
    return {
        "nlp_score": 0,
        "risk_label": "No Input",
        "risk_emoji": "⚪",
        "category_hits": {},
        "top_triggers": [],
    }
