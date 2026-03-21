"""
link_analyzer.py
-----------------
Dual-layer URL analysis:
  Layer 1 — Offline heuristic scanning (instant, no API needed)
  Layer 2 — Real-time threat API lookups (run in parallel):
             • URLhaus (Abuse.ch)  — FREE, no API key required
             • VirusTotal          — FREE tier (optional, set VT_API_KEY in .env)

Each result includes a `timing` dict with per-API latency (ms) and
a `parallel_speedup` metric in the multi-URL result set.
"""

import re
import os
import time
import requests
import validators
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

# ─── Config ───────────────────────────────────────────────────────────────────
VT_API_KEY = os.getenv("VT_API_KEY", "")
REQUEST_TIMEOUT = 4  # seconds per API call (tight — free-tier APIs respond in <2s normally)

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".club", ".work", ".link", ".pw", ".buzz",
}

PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "paypal", "ebay", "amazon", "apple", "microsoft",
    "free", "prize", "winner", "click", "urgent", "suspended",
    "password", "credential", "auth", "signin", "wallet", "crypto",
]

SUSPICIOUS_PATTERNS = [
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Raw IP address used instead of domain"),
    (r"@", "@ symbol in URL — possible redirect trick"),
    (r"bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|rebrand\.ly|short\.io", "URL shortener detected"),
    (r"[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.", "Suspicious hyphenated subdomain pattern"),
]


# ─── Layer 1: Heuristic Analysis ──────────────────────────────────────────────

def _heuristic_scan(url: str) -> list:
    flags = []
    url_lower = url.lower()

    if not bool(validators.url(url)):
        flags.append("⚠️ Invalid URL format")

    for tld in SUSPICIOUS_TLDS:
        if tld in url_lower:
            flags.append(f"🚩 High-risk TLD: `{tld}`")
            break

    found_kw = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    if found_kw:
        flags.append(f"🎣 Phishing keywords: **{', '.join(found_kw[:4])}**")

    for pattern, label in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            flags.append(f"🔍 {label}")

    if len(url) > 100:
        flags.append(f"📏 Unusually long URL ({len(url)} chars)")

    if not url.startswith("https://"):
        flags.append("🔓 No HTTPS — insecure connection")

    return flags


# ─── Layer 2a: URLhaus ────────────────────────────────────────────────────────

def _urlhaus_lookup(url: str) -> tuple:
    """Returns (result_dict, latency_ms)."""
    t0 = time.perf_counter()
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=REQUEST_TIMEOUT,
        )
        ms = int((time.perf_counter() - t0) * 1000)
        if resp.status_code != 200:
            return {"found": False, "threat": "", "status": "api_error"}, ms
        data = resp.json()
        if data.get("query_status") == "is_listed":
            return {"found": True, "threat": data.get("threat", "malware"),
                    "status": data.get("url_status", "unknown")}, ms
        return {"found": False, "threat": "", "status": "not_listed"}, ms
    except Exception:
        ms = int((time.perf_counter() - t0) * 1000)
        return {"found": False, "threat": "", "status": "timeout"}, ms


# ─── Layer 2b: VirusTotal ─────────────────────────────────────────────────────

def _virustotal_lookup(url: str) -> tuple:
    """Returns (result_dict, latency_ms)."""
    t0 = time.perf_counter()
    if not VT_API_KEY:
        return {"found": False, "malicious": 0, "total": 0, "status": "no_key"}, 0

    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        ms = int((time.perf_counter() - t0) * 1000)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            return {"found": True, "malicious": malicious + suspicious,
                    "total": total, "status": "ok"}, ms
        return {"found": False, "malicious": 0, "total": 0, "status": "not_found"}, ms
    except Exception:
        ms = int((time.perf_counter() - t0) * 1000)
        return {"found": False, "malicious": 0, "total": 0, "status": "error"}, ms


# ─── Main Analysis Function ───────────────────────────────────────────────────

def analyze_url(url: str, use_threat_api: bool = True) -> dict:
    """
    Full dual-layer analysis of a single URL.
    URLhaus and VirusTotal calls run in parallel to reduce latency.

    Result includes a `timing` dict:
        {
          "heuristic_ms": int,       # offline scan time
          "urlhaus_ms":   int,       # URLhaus API round-trip
          "virustotal_ms": int,      # VirusTotal API round-trip (0 if skipped)
          "total_ms":     int,       # wall-clock time for this URL
          "api_sequential_ms": int,  # sum of individual API times (for speedup calc)
        }
    """
    if not url or not url.strip():
        return _empty_result(url)

    url = url.strip()

    # ── Heuristic scan (offline) ──
    t_heur = time.perf_counter()
    flags = _heuristic_scan(url)
    heuristic_ms = int((time.perf_counter() - t_heur) * 1000)

    threat_intel = {"urlhaus": None, "virustotal": None}
    confirmed_malicious = False
    urlhaus_ms = 0
    virustotal_ms = 0

    t_apis = time.perf_counter()

    if use_threat_api:
        # Run both API calls in parallel
        with ThreadPoolExecutor(max_workers=2) as executor:
            f_uh = executor.submit(_urlhaus_lookup, url)
            f_vt = executor.submit(_virustotal_lookup, url) if VT_API_KEY else None

        uh, urlhaus_ms = f_uh.result()
        threat_intel["urlhaus"] = uh
        if uh.get("found"):
            confirmed_malicious = True
            flags.insert(0, f"🚨 **URLhaus BLACKLISTED** — Threat: `{uh['threat']}` | Status: `{uh['status']}`")

        if f_vt is not None:
            vt, virustotal_ms = f_vt.result()
            threat_intel["virustotal"] = vt
            if vt.get("found") and vt.get("malicious", 0) > 0:
                confirmed_malicious = True
                flags.insert(
                    0 if not uh.get("found") else 1,
                    f"🦠 **VirusTotal**: {vt['malicious']}/{vt['total']} engines flagged as malicious",
                )

    api_wall_ms = int((time.perf_counter() - t_apis) * 1000)
    total_ms = heuristic_ms + api_wall_ms

    # Risk classification
    if confirmed_malicious:
        risk_level, risk_emoji, deduction = "Critical", "🔴", 40
    elif len(flags) >= 4:
        risk_level, risk_emoji, deduction = "High", "🔴", 30
    elif len(flags) >= 2:
        risk_level, risk_emoji, deduction = "Medium", "🟡", 15
    elif len(flags) == 1:
        risk_level, risk_emoji, deduction = "Low", "🟠", 5
    else:
        risk_level, risk_emoji, deduction = "Safe", "✅", 0

    return {
        "url": url,
        "is_valid": bool(validators.url(url)),
        "risk_level": risk_level,
        "risk_emoji": risk_emoji,
        "flags": flags,
        "deduction": deduction,
        "threat_intel": threat_intel,
        "confirmed_malicious": confirmed_malicious,
        "timing": {
            "heuristic_ms": heuristic_ms,
            "urlhaus_ms": urlhaus_ms,
            "virustotal_ms": virustotal_ms,
            "api_wall_ms": api_wall_ms,
            "api_sequential_ms": urlhaus_ms + virustotal_ms,
            "total_ms": total_ms,
        },
    }


def analyze_multiple_urls(urls_text: str, use_threat_api: bool = True) -> list:
    """
    Parses newline-separated URLs and analyzes each one concurrently.

    The returned list has an extra sentinel at position 0 (a metadata dict)
    with key `_telemetry` for multi-URL parallel speedup:
        {
          "_telemetry": True,
          "wall_ms":        int,   # total wall-clock time for all URLs
          "sequential_ms":  int,   # sum of per-URL total_ms (what it would take sequentially)
          "speedup":        float, # sequential_ms / wall_ms  (>1 means parallel was faster)
          "url_count":      int,
        }
    """
    urls = [line.strip() for line in urls_text.splitlines() if line.strip()]
    if not urls:
        return []

    results = [None] * len(urls)
    t_wall = time.perf_counter()

    with ThreadPoolExecutor(max_workers=min(len(urls), 4)) as executor:
        future_to_idx = {
            executor.submit(analyze_url, url, use_threat_api): i
            for i, url in enumerate(urls)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                results[idx] = _empty_result(urls[idx])
                results[idx]["flags"] = [f"⚠️ Analysis error: {e}"]
                results[idx]["timing"] = {
                    "heuristic_ms": 0, "urlhaus_ms": 0, "virustotal_ms": 0,
                    "api_wall_ms": 0, "api_sequential_ms": 0, "total_ms": 0,
                }

    wall_ms = int((time.perf_counter() - t_wall) * 1000)
    sequential_ms = sum(r.get("timing", {}).get("total_ms", 0) for r in results)
    speedup = round(sequential_ms / wall_ms, 2) if wall_ms > 0 else 1.0

    # Prepend a telemetry metadata sentinel (filtered out in app.py)
    telemetry = {
        "_telemetry": True,
        "wall_ms": wall_ms,
        "sequential_ms": sequential_ms,
        "speedup": speedup,
        "url_count": len(urls),
    }

    return [telemetry] + results


def get_total_url_deduction(url_results: list) -> int:
    """Total deduction capped at 40. Filters out the telemetry sentinel."""
    return min(
        sum(r.get("deduction", 0) for r in url_results if not r.get("_telemetry")),
        40,
    )


def _empty_result(url: str) -> dict:
    return {
        "url": url or "",
        "is_valid": False,
        "risk_level": "Unknown",
        "risk_emoji": "⚪",
        "flags": ["No URL provided"],
        "deduction": 0,
        "threat_intel": {},
        "confirmed_malicious": False,
        "timing": {
            "heuristic_ms": 0, "urlhaus_ms": 0, "virustotal_ms": 0,
            "api_wall_ms": 0, "api_sequential_ms": 0, "total_ms": 0,
        },
    }
