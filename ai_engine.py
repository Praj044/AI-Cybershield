"""
ai_engine.py
-------------
Calls the Gemini REST API directly via `requests`.
This approach avoids all SDK version / model-name compatibility issues.
It auto-discovers the first available generateContent model for this API key,
with a hardcoded fallback list so the app works even when the list API is down.
"""

import os
import requests
from dotenv import load_dotenv
from pathlib import Path

# Load .env from project root
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

_api_key = None
_model_id = None  # cached after first successful discovery

# Fallback model list (tried in order if discovery fails)
_FALLBACK_MODELS = [
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-flash-latest",
    "gemini-1.5-pro",
    "gemini-1.0-pro",
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_api_key() -> str:
    global _api_key
    if _api_key is None:
        _api_key = os.getenv("GEMINI_API_KEY", "")
        if not _api_key:
            raise ValueError("GEMINI_API_KEY not found in .env")
    return _api_key


def _get_model() -> str:
    """
    Returns the best available generateContent model for this API key.
    Tries live model discovery first; falls back to a hardcoded list if
    the models endpoint is unavailable or rate-limited.
    """
    global _model_id
    if _model_id:
        return _model_id

    key = _get_api_key()

    # ── Try live discovery ──
    try:
        resp = requests.get(
            f"{BASE_URL}/models?key={key}",
            timeout=8,
        )
        if resp.status_code == 200:
            models = resp.json().get("models", [])
            candidates = [
                m["name"].replace("models/", "")
                for m in models
                if "generateContent" in m.get("supportedGenerationMethods", [])
            ]
            if candidates:
                # Prefer flash for speed; otherwise take the first candidate
                preferred = next(
                    (m for m in candidates if "flash" in m.lower()), None
                )
                _model_id = preferred or candidates[0]
                print(f"[ai_engine] Discovered model: {_model_id}")
                return _model_id
    except Exception as disc_err:
        print(f"[ai_engine] Model discovery failed ({disc_err}), trying fallbacks…")

    # ── Fallback: probe each hardcoded model until one responds ──
    for model in _FALLBACK_MODELS:
        try:
            test_url = f"{BASE_URL}/models/{model}:generateContent?key={key}"
            probe = requests.post(
                test_url,
                json={"contents": [{"parts": [{"text": "ping"}]}]},
                timeout=8,
            )
            # 200 or 400 (bad request) both mean the model exists
            if probe.status_code in (200, 400):
                _model_id = model
                print(f"[ai_engine] Using fallback model: {_model_id}")
                return _model_id
        except Exception:
            continue

    raise RuntimeError(
        "No generateContent-capable Gemini model found. "
        "Check your GEMINI_API_KEY and internet connection."
    )


def _generate(prompt: str, max_tokens: int = 400) -> str:
    """Calls generateContent REST endpoint and returns the text response."""
    key = _get_api_key()
    model = _get_model()

    url = f"{BASE_URL}/models/{model}:generateContent?key={key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": max_tokens},
    }

    resp = requests.post(url, json=payload, timeout=30)
    resp.raise_for_status()

    data = resp.json()
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"Unexpected API response format: {data}") from e


# ─── Public API ───────────────────────────────────────────────────────────────

def analyze_email_for_phishing(email_text: str) -> dict:
    """
    Sends email content to Gemini and asks it to detect phishing indicators.
    """
    if not email_text or not email_text.strip():
        return {
            "is_phishing": False,
            "confidence": "N/A",
            "risk_emoji": "⚪",
            "explanation": "No email content provided.",
            "red_flags": [],
            "deduction": 0,
        }

    prompt = f"""
You are a cybersecurity expert specializing in phishing detection.

Analyze the following email and respond in EXACTLY this format (no extra text):

VERDICT: YES or NO
CONFIDENCE: High or Medium or Low
RED_FLAGS:
- flag one
- flag two
EXPLANATION: One plain-English sentence explaining the verdict.

Email:
---
{email_text}
---
"""

    try:
        raw = _generate(prompt, max_tokens=400)
        return _parse_response(raw.strip())
    except Exception as e:
        return _error_result(str(e))


def get_security_explanation(context: dict) -> dict:
    """
    Generates structured, issue-specific security advice using Gemini.

    Returns a dict with:
      - "sections": list of {"icon": str, "title": str, "body": str}
      - "summary":  one encouraging closing sentence
    """
    score   = context.get("score", 0)
    pw_lbl  = context.get("password_label", "Not checked")
    pw_scr  = context.get("password_score", -1)       # 0-4, -1 = not checked
    is_ph   = context.get("is_phishing", False)
    ph_conf = context.get("phishing_confidence", "N/A")
    ph_flgs = context.get("red_flags", [])
    url_risk= context.get("url_risk", "N/A")
    url_lst = context.get("risky_urls", [])

    # Build a specific issue list so the prompt is grounded in real data
    issues = []
    if pw_scr >= 0 and pw_scr < 4:
        issues.append(f"Password is '{pw_lbl}' (strength {pw_scr}/4)")
    if is_ph:
        flags_str = "; ".join(ph_flgs[:3]) if ph_flgs else "none listed"
        issues.append(f"Phishing email detected (confidence: {ph_conf}). Red flags: {flags_str}")
    if url_risk in ("Critical", "High", "Medium"):
        urls_str = ", ".join(url_lst[:3]) if url_lst else "one or more URLs"
        issues.append(f"Risky URLs found (risk level: {url_risk}): {urls_str}")

    if not issues:
        issues_text = "No critical issues found – the scan looks clean."
    else:
        issues_text = "\n".join(f"- {i}" for i in issues)

    prompt = f"""You are a warm, expert cybersecurity coach giving personalized advice after a security scan.

DETECTED ISSUES:
{issues_text}

Overall Score: {score}/100

Give advice ONLY for the issues listed above. If no issues are listed, give a brief congratulations.
Structure your response EXACTLY as below (one block per issue, skip blocks for issues not present):

[PASSWORD]
<2-3 specific, actionable sentences about fixing the password weakness>

[PHISHING]
<2-3 specific sentences about the phishing indicators found and what the user should do>

[URL]
<2-3 specific sentences about the risky URL(s) and what to do>

[SUMMARY]
<One warm, encouraging closing sentence that mentions the score>

Rules:
- Use plain English, no jargon
- Be specific (reference the actual issue, not generic advice)
- Do NOT add any extra headings or text outside these blocks
- Skip blocks completely if that issue is not in the detected list
"""

    try:
        raw = _generate(prompt, max_tokens=450).strip()
        return _parse_advice(raw, score)
    except Exception as e:
        return _fallback_advice(context, str(e))


def _parse_advice(raw: str, score: int) -> dict:
    """Parses the structured Gemini response into sections."""
    import re

    sections = []
    summary = ""

    # Split on [SECTION] headers
    block_map = {
        "PASSWORD": ("🔐", "Password Security"),
        "PHISHING": ("📧", "Phishing Email"),
        "URL":      ("🔗", "URL Threat"),
        "SUMMARY":  ("✨", "Overall"),
    }

    pattern = re.compile(r'\[(PASSWORD|PHISHING|URL|SUMMARY)\]', re.IGNORECASE)
    parts = pattern.split(raw)

    # parts[0] is text before first header (usually empty), then alternating key/body pairs
    i = 1
    while i < len(parts) - 1:
        key  = parts[i].strip().upper()
        body = parts[i + 1].strip()
        i += 2
        if not body:
            continue
        if key == "SUMMARY":
            summary = body
        elif key in block_map:
            icon, title = block_map[key]
            sections.append({"icon": icon, "title": title, "body": body})

    if not summary:
        summary = f"Your current security score is {score}/100 — keep improving! 🚀"

    return {"sections": sections, "summary": summary}


def _fallback_advice(context: dict, error: str) -> dict:
    """Rule-based fallback when Gemini is unavailable."""
    sections = []
    score   = context.get("score", 0)
    pw_scr  = context.get("password_score", -1)
    is_ph   = context.get("is_phishing", False)
    url_risk= context.get("url_risk", "N/A")

    if pw_scr >= 0 and pw_scr < 4:
        sections.append({
            "icon": "🔐", "title": "Password Security",
            "body": ("Your password is weak. Use a passphrase of 4+ random words mixed with "
                     "numbers and symbols (e.g. Tiger#Flame!Orbit92). Enable a password manager "
                     "like Bitwarden or 1Password to generate and store strong passwords.")
        })
    if is_ph:
        sections.append({
            "icon": "📧", "title": "Phishing Email",
            "body": ("This email shows phishing indicators. Do not click any links or download "
                     "attachments. Report it to your email provider as phishing and delete it. "
                     "When in doubt, contact the sender directly via a known verified channel.")
        })
    if url_risk in ("Critical", "High", "Medium"):
        sections.append({
            "icon": "🔗", "title": "URL Threat",
            "body": ("One or more URLs in your scan are flagged as risky. Avoid visiting them. "
                     "If you already clicked, run an antivirus scan immediately. Always verify "
                     "URLs match the official domain before entering credentials.")
        })

    summary = f"Your security score is {score}/100. " + (
        "Great job staying safe! 🎉" if score >= 80 else
        "Follow the guidance above to improve your digital safety. 💪"
    )
    return {"sections": sections, "summary": summary}



# ─── Parser ───────────────────────────────────────────────────────────────────

def _parse_response(raw: str) -> dict:
    verdict = False
    confidence = "Low"
    flags = []
    explanation = ""
    reading_flags = False

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        upper = line.upper()
        if upper.startswith("VERDICT"):
            verdict = "YES" in upper
        elif upper.startswith("CONFIDENCE"):
            parts = line.split(":", 1)
            confidence = parts[1].strip() if len(parts) > 1 else "Low"
        elif upper.startswith("RED_FLAGS"):
            reading_flags = True
        elif upper.startswith("EXPLANATION"):
            reading_flags = False
            parts = line.split(":", 1)
            explanation = parts[1].strip() if len(parts) > 1 else ""
        elif reading_flags and line.startswith("-"):
            flags.append(line[1:].strip())

    deduction = 50 if verdict else (20 if confidence.lower() == "medium" else 0)
    emoji = "🔴" if verdict else ("🟡" if confidence.lower() == "medium" else "✅")

    return {
        "is_phishing": verdict,
        "confidence": confidence,
        "risk_emoji": emoji,
        "explanation": explanation,
        "red_flags": flags,
        "deduction": deduction,
    }


def _error_result(msg: str) -> dict:
    return {
        "is_phishing": False,
        "confidence": "Error",
        "risk_emoji": "⚠️",
        "explanation": msg,
        "red_flags": [],
        "deduction": 0,
    }