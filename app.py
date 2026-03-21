"""
app.py — AI CyberShield Premium Dashboard
"""

import os
import time
import streamlit as st
from password_checker import check_password_strength, get_score_deduction, generate_strong_password
from link_analyzer import analyze_multiple_urls, get_total_url_deduction
from ai_engine import analyze_email_for_phishing, get_security_explanation
from phishing_nlp import score_phishing_nlp
from ml_phishing import classify_email_ml
from score_calculator import calculate_security_score

# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI CyberShield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Premium CSS ──────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');


*, html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
}

/* ── Background ── */
.stApp {
    background: radial-gradient(ellipse at 20% 50%, #0d1f3c 0%, #080d1a 60%),
                radial-gradient(ellipse at 80% 20%, #0a1628 0%, transparent 60%);
    background-color: #070c18;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a1628 0%, #070c18 100%);
    border-right: 1px solid rgba(56,189,248,0.12);
}

/* ── Metric cards ── */
[data-testid="stMetric"] {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(56,189,248,0.15);
    border-radius: 12px;
    padding: 1rem !important;
    backdrop-filter: blur(10px);
    transition: border-color 0.3s;
}
[data-testid="stMetric"]:hover { border-color: rgba(56,189,248,0.4); }
[data-testid="stMetricLabel"] { color: #94a3b8 !important; font-size: 0.75rem !important; text-transform: uppercase; letter-spacing: 0.1em; }
[data-testid="stMetricValue"] { color: #f0f6ff !important; font-weight: 700 !important; }

/* ── Inputs ── */
.stTextInput input, .stTextArea textarea {
    background: rgba(255,255,255,0.04) !important;
    border: 1px solid rgba(56,189,248,0.2) !important;
    border-radius: 10px !important;
    color: #e2e8f0 !important;
    font-family: 'JetBrains Mono', monospace !important;
    transition: border-color 0.3s, box-shadow 0.3s;
}
.stTextInput input:focus, .stTextArea textarea:focus {
    border-color: rgba(56,189,248,0.6) !important;
    box-shadow: 0 0 0 3px rgba(56,189,248,0.1) !important;
}


/* ── Scan button ── */
.stButton > button {
    background: linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%);
    color: white !important;
    border: none !important;
    border-radius: 12px !important;
    font-weight: 700 !important;
    font-size: 1rem !important;
    padding: 0.75rem 2.5rem !important;
    letter-spacing: 0.05em;
    transition: all 0.3s ease !important;
    box-shadow: 0 4px 20px rgba(14,165,233,0.3) !important;
    width: 100% !important;
}
.stButton > button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 30px rgba(14,165,233,0.5) !important;
}

/* ── Expander ── */
div[data-testid="stExpander"] {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(56,189,248,0.12) !important;
    border-radius: 12px !important;
}


/* ── Divider ── */
hr { border-color: rgba(56,189,248,0.1) !important; }

/* ── Progress bar ── */
.stProgress > div > div { background: linear-gradient(90deg, #0ea5e9, #6366f1) !important; }

/* ── Custom components ── */
.cyber-card {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(56,189,248,0.15);
    border-radius: 16px;
    padding: 1.5rem;
    backdrop-filter: blur(12px);
    margin-bottom: 1rem;
    transition: all 0.3s;
}
.cyber-card:hover { border-color: rgba(56,189,248,0.35); }

.score-ring-wrap {
    background: radial-gradient(circle at center, rgba(14,165,233,0.08) 0%, transparent 70%);
    border: 1px solid rgba(56,189,248,0.2);
    border-radius: 20px;
    padding: 2rem 1.5rem;
    text-align: center;
}

.score-value {
    font-size: 5.5rem;
    font-weight: 800;
    line-height: 1;
    letter-spacing: -0.04em;
    background: linear-gradient(135deg, var(--sc), white);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.score-label {
    font-size: 1.1rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-top: 0.4rem;
    opacity: 0.75;
}

.flag-critical {
    background: rgba(239,68,68,0.1);
    border-left: 3px solid #ef4444;
    border-radius: 0 8px 8px 0;
    padding: 0.5rem 1rem;
    margin: 0.3rem 0;
    font-size: 0.875rem;
    color: #fca5a5;
}
.flag-warning {
    background: rgba(234,179,8,0.1);
    border-left: 3px solid #eab308;
    border-radius: 0 8px 8px 0;
    padding: 0.5rem 1rem;
    margin: 0.3rem 0;
    font-size: 0.875rem;
    color: #fde047;
}
.flag-safe {
    background: rgba(34,197,94,0.1);
    border-left: 3px solid #22c55e;
    border-radius: 0 8px 8px 0;
    padding: 0.5rem 1rem;
    margin: 0.3rem 0;
    font-size: 0.875rem;
    color: #86efac;
}

.nlp-bar-wrap {
    background: rgba(255,255,255,0.05);
    border-radius: 8px;
    height: 10px;
    overflow: hidden;
    margin: 0.3rem 0 0.8rem 0;
}
.nlp-bar-fill {
    height: 100%;
    border-radius: 8px;
    background: linear-gradient(90deg, #22c55e, #eab308, #ef4444);
    transition: width 0.8s ease;
}

.threat-badge {
    display: inline-block;
    padding: 0.2rem 0.7rem;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}
.badge-danger { background: rgba(239,68,68,0.2); color: #fca5a5; border: 1px solid rgba(239,68,68,0.4); }
.badge-warn   { background: rgba(234,179,8,0.2);  color: #fde047; border: 1px solid rgba(234,179,8,0.4); }
.badge-safe   { background: rgba(34,197,94,0.2);  color: #86efac; border: 1px solid rgba(34,197,94,0.4); }
.badge-info   { background: rgba(14,165,233,0.2); color: #7dd3fc; border: 1px solid rgba(14,165,233,0.4); }

.section-header {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    color: #0ea5e9;
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.ai-advice-box {
    background: linear-gradient(135deg, rgba(14,165,233,0.08), rgba(99,102,241,0.08));
    border: 1px solid rgba(99,102,241,0.25);
    border-radius: 16px;
    padding: 1.5rem;
    font-size: 0.95rem;
    line-height: 1.75;
    color: #cbd5e1;
}
</style>
""", unsafe_allow_html=True)


# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 1.5rem 0 1rem;">
        <div style="font-size:3rem;">🛡️</div>
        <div style="font-size:1.3rem; font-weight:800; color:#f0f6ff; letter-spacing:-0.02em;">AI CyberShield</div>
        <div style="font-size:0.75rem; color:#64748b; letter-spacing:0.08em; text-transform:uppercase; margin-top:0.3rem;">Personal Security Assistant</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown("""
    <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(56,189,248,0.12);
         border-radius:12px; padding:1rem; margin-bottom:0.75rem;">
        <div style="font-size:0.7rem; color:#0ea5e9; font-weight:600; text-transform:uppercase;
             letter-spacing:0.1em; margin-bottom:0.6rem;">How to Use</div>
        <ol style="color:#94a3b8; font-size:0.82rem; margin:0; padding-left:1.2rem; line-height:1.8;">
            <li>Fill in <b style="color:#cbd5e1">any</b> field below</li>
            <li>Click <b style="color:#cbd5e1">Run Security Scan</b></li>
            <li>Review your score &amp; AI advice</li>
            <li>Fix the flagged issues</li>
        </ol>
    </div>

    <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(56,189,248,0.12);
         border-radius:12px; padding:1rem; margin-bottom:0.75rem;">
        <div style="font-size:0.7rem; color:#0ea5e9; font-weight:600; text-transform:uppercase;
             letter-spacing:0.1em; margin-bottom:0.75rem;">Scoring Guide</div>
        <table style="width:100%; border-collapse:collapse; font-size:0.82rem; color:#94a3b8;">
            <tr style="border-bottom:1px solid rgba(56,189,248,0.1);">
                <th style="text-align:left; padding:0.3rem 0; color:#64748b;">Score</th>
                <th style="text-align:left; padding:0.3rem 0; color:#64748b;">Grade</th>
            </tr>
            <tr><td style="padding:0.3rem 0;">90–100</td><td>🛡️ Excellent</td></tr>
            <tr><td style="padding:0.3rem 0;">70–89</td><td>✅ Good</td></tr>
            <tr><td style="padding:0.3rem 0;">50–69</td><td>🟡 Fair</td></tr>
            <tr><td style="padding:0.3rem 0;">30–49</td><td>🟠 Poor</td></tr>
            <tr><td style="padding:0.3rem 0;">0–29</td><td>🔴 Critical</td></tr>
        </table>
        <div style="margin-top:0.75rem; font-size:0.78rem; color:#64748b; line-height:1.7;">
            <b style="color:#94a3b8;">Deductions:</b><br>
            🔐 Weak password: up to −40<br>
            📧 Phishing email: up to −50<br>
            🔗 Risky URLs: up to −40
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    use_threat_api = st.toggle("Real-Time Threat API", value=True,
        help="Query URLhaus (Abuse.ch) to check URLs against live blacklists")

    # Show active threat intel status
    _vt_active = bool(os.getenv("VT_API_KEY", ""))
    st.markdown(f"""
    <div style="margin-top:0.75rem;">
        <div style="font-size:0.7rem; color:#64748b; text-transform:uppercase; letter-spacing:0.1em; margin-bottom:0.5rem;">Threat Intel Status</div>
        <div style="display:flex; flex-direction:column; gap:0.35rem;">
            <div style="display:flex; align-items:center; gap:0.5rem; font-size:0.8rem;">
                <span style="color:{'#22c55e' if use_threat_api else '#ef4444'};">{'●' if use_threat_api else '○'}</span>
                <span style="color:#94a3b8;">URLhaus</span>
                <span style="color:{'#22c55e' if use_threat_api else '#64748b'}; font-size:0.7rem;">{'ACTIVE' if use_threat_api else 'OFF'}</span>
            </div>
            <div style="display:flex; align-items:center; gap:0.5rem; font-size:0.8rem;">
                <span style="color:{'#22c55e' if _vt_active else '#64748b'};">{'●' if _vt_active else '○'}</span>
                <span style="color:#94a3b8;">VirusTotal</span>
                <span style="color:{'#22c55e' if _vt_active else '#64748b'}; font-size:0.7rem;">{'ACTIVE' if _vt_active else 'NO KEY'}</span>
            </div>
            <div style="display:flex; align-items:center; gap:0.5rem; font-size:0.8rem;">
                <span style="color:#22c55e;">●</span>
                <span style="color:#94a3b8;">ML Classifier</span>
                <span style="color:#22c55e; font-size:0.7rem;">OFFLINE</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)



# ─── Header ───────────────────────────────────────────────────────────────────
st.markdown("""
<div style="padding: 2rem 0 1rem;">
    <div style="font-size:2.25rem; font-weight:800; color:#f0f6ff; letter-spacing:-0.03em;">
        🛡️ AI <span style="background: linear-gradient(135deg,#0ea5e9,#6366f1);
        -webkit-background-clip:text;-webkit-text-fill-color:transparent;">CyberShield</span>
    </div>
    <div style="font-size:1rem; color:#64748b; margin-top:0.4rem;">
        Real-time phishing detection · Password auditing · URL threat intelligence
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# ─── Input Section ────────────────────────────────────────────────────────────
col1, col2 = st.columns([1, 1], gap="large")

with col1:
    st.markdown('<div class="section-header">🔐 Password Audit</div>', unsafe_allow_html=True)
    password_input = st.text_input(
        "Enter a password:", type="password",
        placeholder="Try: hunter2 vs Tr0ub4dor&3",
        label_visibility="collapsed",
    )
    if password_input:
        pr = check_password_strength(password_input)
        bar_pct = int((pr["score"] / 4) * 100)
        bar_colors = ["#ef4444","#f97316","#eab308","#22c55e","#10b981"]
        bar_color = bar_colors[pr["score"]]
        st.markdown(f"""
        <div style="margin-top:0.5rem;">
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                <span style="font-size:0.8rem; color:#94a3b8;">Strength</span>
                <span style="font-size:0.8rem; font-weight:600; color:{bar_color};">
                    {pr['emoji']} {pr['label']}
                </span>
            </div>
            <div style="background:rgba(255,255,255,0.08); border-radius:6px; height:8px; overflow:hidden;">
                <div style="width:{bar_pct}%; height:100%; background:{bar_color}; border-radius:6px; transition:width 0.5s;"></div>
            </div>
            <div style="font-size:0.75rem; color:#64748b; margin-top:0.4rem;">
                ⏱️ Crack time: <b style="color:#94a3b8">{pr['crack_time']}</b>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="section-header" style="margin-top:1.5rem;">🔗 URL Threat Scanner</div>', unsafe_allow_html=True)
    url_input = st.text_area(
        "URLs:", placeholder="https://paypal-login-verify.xyz\nhttps://google.com",
        height=120, label_visibility="collapsed",
    )

with col2:
    st.markdown('<div class="section-header">📧 Email Phishing Analyzer</div>', unsafe_allow_html=True)
    email_input = st.text_area(
        "Email:", height=285,
        placeholder="Paste full email content here...\n\nExample:\nDear user, Your account has been SUSPENDED. Click here IMMEDIATELY to verify your details or your account will be permanently deleted within 24 hours.",
        label_visibility="collapsed",
    )
    if email_input:
        nlp = score_phishing_nlp(email_input)
        st.markdown(f"""
        <div style="margin-top:0.5rem;">
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                <span style="font-size:0.8rem; color:#94a3b8;">NLP Phishing Score</span>
                <span style="font-size:0.8rem; font-weight:600;">{nlp['risk_emoji']} {nlp['nlp_score']}/100 — {nlp['risk_label']}</span>
            </div>
            <div class="nlp-bar-wrap">
                <div class="nlp-bar-fill" style="width:{nlp['nlp_score']}%;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("---")

scan_btn = st.button("🔍  Run Security Scan", key="scan_btn")

# ─── Scan Logic ───────────────────────────────────────────────────────────────
if scan_btn:
    if not any([password_input, email_input, url_input]):
        st.warning("⚠️ Please fill in at least one field.")
        st.stop()

    with st.spinner("🤖 Scanning... running all checks in parallel ⚡"):
        from concurrent.futures import ThreadPoolExecutor as _TPE
        import time as _time
        _t_scan_start = time.perf_counter()

        # ── Timed wrappers — each records its own wall-clock time ────────────
        def _run_password():
            t0 = _time.perf_counter()
            res = check_password_strength(password_input) if password_input else None
            return res, int((_time.perf_counter() - t0) * 1000)

        def _run_nlp():
            t0 = _time.perf_counter()
            res = score_phishing_nlp(email_input) if email_input else None
            return res, int((_time.perf_counter() - t0) * 1000)

        def _run_ai():
            t0 = _time.perf_counter()
            res = analyze_email_for_phishing(email_input) if email_input else None
            return res, int((_time.perf_counter() - t0) * 1000)

        def _run_url():
            t0 = _time.perf_counter()
            res = analyze_multiple_urls(url_input, use_threat_api) if url_input else []
            return res, int((_time.perf_counter() - t0) * 1000)

        def _run_ml():
            t0 = _time.perf_counter()
            res = classify_email_ml(email_input) if email_input else None
            return res, int((_time.perf_counter() - t0) * 1000)

        # ── Fire ALL 5 tasks simultaneously ─────────────────────────────────
        with _TPE(max_workers=5) as _ex:
            _f_pw  = _ex.submit(_run_password)
            _f_nlp = _ex.submit(_run_nlp)
            _f_ai  = _ex.submit(_run_ai)
            _f_url = _ex.submit(_run_url)
            _f_ml  = _ex.submit(_run_ml)

        # ── Collect results (all futures already done at this point) ─────────
        pw_result,      _pw_ms  = _f_pw.result()
        nlp_result,     _nlp_ms = _f_nlp.result()
        email_result,   _ai_ms  = _f_ai.result()
        url_results_raw, _url_ms = _f_url.result()
        ml_result,      _ml_ms  = _f_ml.result()

        pwd_ded = get_score_deduction(pw_result) if pw_result else 0
        ph_ded  = email_result["deduction"] if email_result else 0

        # Extract telemetry sentinel and actual URL results
        _url_telemetry = None
        if url_results_raw and url_results_raw[0].get("_telemetry"):
            _url_telemetry = url_results_raw[0]
            url_results = url_results_raw[1:]
        else:
            url_results = url_results_raw

        url_ded = get_total_url_deduction(url_results)

        # ── Security score (instant) ─────────────────────────────────────────
        score_result = calculate_security_score(pwd_ded, ph_ded, url_ded)

        _scan_total_ms = int((time.perf_counter() - _t_scan_start) * 1000)
        # Sequential estimate = sum of all individual task times
        _sequential_estimate_ms = _pw_ms + _nlp_ms + _ai_ms + _url_ms + _ml_ms

        # URL risk label for AI
        url_risk_label = "N/A"
        if url_results:
            if any(r["confirmed_malicious"] for r in url_results):
                url_risk_label = "Critical"
            elif any(r["risk_level"] == "High" for r in url_results):
                url_risk_label = "High"
            elif url_ded > 0:
                url_risk_label = "Medium"
            else:
                url_risk_label = "Low"

        # Collect risky URL strings for advisor context
        _risky_url_list = [
            r.get("url", "") for r in url_results
            if r.get("risk_level") in ("High", "Critical") or r.get("confirmed_malicious")
        ] if url_results else []

        ai_advice = get_security_explanation({
            "score":                score_result["score"],
            "password_label":       pw_result["label"] if pw_result else "Not checked",
            "password_score":       pw_result["score"] if pw_result else -1,
            "is_phishing":          email_result["is_phishing"] if email_result else False,
            "phishing_confidence":  email_result["confidence"] if email_result else "N/A",
            "red_flags":            email_result["red_flags"] if email_result else [],
            "url_risk":             url_risk_label,
            "risky_urls":           _risky_url_list,
        })

    st.success("✅ Scan complete!")
    st.markdown("---")

    # ── Results Layout ────────────────────────────────────────────────────────
    left, right = st.columns([1, 2], gap="large")

    with left:
        # ── Score Card ──
        score = score_result["score"]
        color = score_result["color"]
        grade = score_result["grade"]
        emoji = score_result["emoji"]

        st.markdown(f"""
        <div class="score-ring-wrap">
            <div style="font-size:0.65rem; color:#64748b; letter-spacing:0.2em; text-transform:uppercase; margin-bottom:0.5rem;">Security Score</div>
            <div class="score-value" style="--sc:{color}; color:{color};">{score}</div>
            <div style="font-size:0.8rem; color:#475569; margin-top:0.25rem;">out of 100</div>
            <div class="score-label" style="color:{color};">{emoji} {grade}</div>
        </div>
        """, unsafe_allow_html=True)

        # Progress bar
        st.markdown("<div style='margin-top:1rem;'></div>", unsafe_allow_html=True)
        st.progress(score / 100)

        # Breakdown
        st.markdown("<div style='margin-top:1rem;'></div>", unsafe_allow_html=True)
        st.markdown('<div class="section-header">📊 Score Breakdown</div>', unsafe_allow_html=True)
        b = score_result["breakdown"]

        def _breakdown_row(label, ded, max_ded):
            pct = int((ded / max_ded) * 100) if max_ded else 0
            bar_c = "#22c55e" if ded == 0 else ("#ef4444" if pct > 60 else "#eab308")
            return f"""
            <div style="margin-bottom:0.8rem;">
                <div style="display:flex;justify-content:space-between;font-size:0.8rem;color:#94a3b8;margin-bottom:3px;">
                    <span>{label}</span>
                    <span style="color:{'#ef4444' if ded>0 else '#22c55e'}">-{ded} pts</span>
                </div>
                <div style="background:rgba(255,255,255,0.06);border-radius:4px;height:6px;">
                    <div style="width:{pct}%;height:100%;background:{bar_c};border-radius:4px;"></div>
                </div>
            </div>"""

        st.markdown(
            _breakdown_row("🔐 Password", b["password_deduction"], 40) +
            _breakdown_row("📧 Phishing", b["phishing_deduction"], 50) +
            _breakdown_row("🔗 URL Risk", b["url_deduction"], 40),
            unsafe_allow_html=True,
        )

    with right:
        # ── Password Results ──────────────────────────────────────────────────
        if pw_result:
            st.markdown('<div class="section-header">🔐 Password Audit Results</div>', unsafe_allow_html=True)
            c1, c2, c3 = st.columns(3)
            c1.metric("Strength", f"{pw_result['emoji']} {pw_result['label']}")
            c2.metric("Score", f"{pw_result['score']} / 4")
            c3.metric("Crack Time", pw_result["crack_time"])
            if pw_result["warning"]:
                st.markdown(f'<div class="flag-warning">⚠️ {pw_result["warning"]}</div>', unsafe_allow_html=True)
            if pw_result["suggestions"]:
                for s in pw_result["suggestions"]:
                    st.markdown(f'<div class="flag-safe">💡 {s}</div>', unsafe_allow_html=True)

            # ── Password Suggestion Card (shown when score < 4) ─────────────────
            if pw_result["score"] < 4:
                suggested = generate_strong_password(3)
                _style_tags = ["🎲 Random Mix", "📝 Passphrase", "⚡ Compact"]
                st.markdown("""
                <div style="margin-top:1rem; background:rgba(14,165,233,0.06);
                            border:1px solid rgba(14,165,233,0.25); border-radius:12px;
                            padding:1rem 1.1rem;">
                    <div style="font-size:0.7rem; color:#0ea5e9; font-weight:700;
                                text-transform:uppercase; letter-spacing:0.1em;
                                margin-bottom:0.8rem;">&#128273; Suggested Strong Passwords</div>
                """, unsafe_allow_html=True)
                for i, pwd in enumerate(suggested):
                    tag = _style_tags[i % len(_style_tags)]
                    st.markdown(f"""
                    <div style="background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08);
                                border-radius:8px; padding:0.65rem 0.9rem; margin-bottom:0.5rem;
                                display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <span style="font-family:'JetBrains Mono',monospace; font-size:0.88rem;
                                         color:#e2e8f0; letter-spacing:0.04em;">{pwd}</span>
                        </div>
                        <div style="display:flex; gap:0.5rem; align-items:center; flex-shrink:0;">
                            <span style="font-size:0.68rem; color:#64748b; white-space:nowrap;">{tag}</span>
                            <span style="background:#22c55e22; color:#22c55e; font-size:0.65rem;
                                         font-weight:600; padding:2px 8px; border-radius:999px;
                                         border:1px solid #22c55e44;">Strong</span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                st.markdown("""<div style="font-size:0.72rem; color:#475569; margin-top:0.4rem;">
                    🔒 Copy a password above and save it in a password manager.
                </div></div>""", unsafe_allow_html=True)
            st.markdown("---")

        # ── Phishing Results ──────────────────────────────────────────────────
        if email_result:
            st.markdown('<div class="section-header">📧 Phishing Analysis</div>', unsafe_allow_html=True)

            # Dual scoring: NLP + AI
            ph_c1, ph_c2 = st.columns(2)
            with ph_c1:
                is_ph = email_result["is_phishing"]
                verdict_color = "#ef4444" if is_ph else "#22c55e"
                verdict_text = "PHISHING DETECTED" if is_ph else "LOOKS SAFE"
                st.markdown(f"""
                <div style="background:{'rgba(239,68,68,0.1)' if is_ph else 'rgba(34,197,94,0.1)'};
                     border:1px solid {'rgba(239,68,68,0.4)' if is_ph else 'rgba(34,197,94,0.4)'};
                     border-radius:12px; padding:1rem; text-align:center;">
                    <div style="font-size:1.5rem;">{'🚨' if is_ph else '✅'}</div>
                    <div style="font-size:0.85rem; font-weight:700; color:{verdict_color}; margin-top:0.3rem;">{verdict_text}</div>
                    <div style="font-size:0.7rem; color:#64748b; margin-top:0.2rem;">AI Confidence: {email_result['confidence']}</div>
                </div>
                """, unsafe_allow_html=True)
            with ph_c2:
                if nlp_result:
                    nlp_score = nlp_result["nlp_score"]
                    st.markdown(f"""
                    <div style="background:rgba(14,165,233,0.08); border:1px solid rgba(14,165,233,0.2);
                         border-radius:12px; padding:1rem; text-align:center;">
                        <div style="font-size:1.5rem;">{nlp_result['risk_emoji']}</div>
                        <div style="font-size:0.85rem; font-weight:700; color:#7dd3fc; margin-top:0.3rem;">NLP Score: {nlp_score}/100</div>
                        <div style="font-size:0.7rem; color:#64748b; margin-top:0.2rem;">{nlp_result['risk_label']}</div>
                    </div>
                    """, unsafe_allow_html=True)

            # ML score card (third column)
            if ml_result:
                _ml_is_phish = ml_result["ml_verdict"]
                _ml_bg    = "rgba(239,68,68,0.08)"   if _ml_is_phish else "rgba(34,197,94,0.08)"
                _ml_bdr   = "rgba(239,68,68,0.25)"   if _ml_is_phish else "rgba(34,197,94,0.25)"
                _ml_tc    = "#fca5a5"                 if _ml_is_phish else "#86efac"
                _feat_pills = ""
                for feat in ml_result["top_features"]:
                    _feat_pills += f'<span style="background:rgba(99,102,241,0.15);color:#a5b4fc;font-size:0.65rem;padding:2px 7px;border-radius:999px;margin:2px;display:inline-block;">{feat}</span>'
                st.markdown(f"""
                <div style="background:{_ml_bg}; border:1px solid {_ml_bdr};
                     border-radius:12px; padding:1rem; margin-top:0.75rem;">
                    <div style="font-size:0.7rem; color:#94a3b8; font-weight:600;
                                text-transform:uppercase; letter-spacing:0.1em; margin-bottom:0.6rem;">
                        🤖&nbsp; ML Classifier
                    </div>
                    <div style="display:flex; align-items:center; gap:0.75rem; margin-bottom:0.5rem;">
                        <span style="font-size:1.8rem; line-height:1;">{ml_result['ml_emoji']}</span>
                        <div>
                            <div style="font-size:0.9rem; font-weight:700; color:{_ml_tc};">{ml_result['ml_label']}</div>
                            <div style="font-size:0.75rem; color:#64748b;">Score: {ml_result['ml_score']}/100 &nbsp;·&nbsp; {ml_result['ml_confidence']} confidence</div>
                        </div>
                    </div>
                    <div style="background:rgba(255,255,255,0.05); border-radius:6px; height:6px; overflow:hidden; margin-bottom:0.6rem;">
                        <div style="width:{ml_result['ml_score']}%; height:100%;
                                    background:{'linear-gradient(90deg,#ef4444,#f97316)' if _ml_is_phish else 'linear-gradient(90deg,#22c55e,#10b981)'};
                                    border-radius:6px; transition:width 0.6s;"></div>
                    </div>
                    {f'<div style="font-size:0.68rem; color:#64748b; margin-bottom:0.25rem;">Top signals:</div><div style="line-height:2;">{_feat_pills}</div>' if _feat_pills else ''}
                </div>
                """, unsafe_allow_html=True)

            # NLP category breakdown
            if nlp_result and nlp_result["category_hits"]:
                st.markdown("<div style='margin-top:0.75rem;'></div>", unsafe_allow_html=True)
                st.markdown('<div class="section-header">🧠 NLP Category Analysis</div>', unsafe_allow_html=True)
                cats = nlp_result["category_hits"]
                rows_html = ""
                for cat, terms in cats.items():
                    terms_str = " · ".join(f'<code style="color:#fde047; background:rgba(234,179,8,0.1); padding:1px 5px; border-radius:4px; font-size:0.7rem">{t}</code>' for t in terms)
                    rows_html += f'<div style="margin-bottom:0.5rem;"><span style="color:#94a3b8;font-size:0.8rem;font-weight:600;">{cat}:</span> {terms_str}</div>'
                st.markdown(f'<div style="margin-top:0.5rem;">{rows_html}</div>', unsafe_allow_html=True)

            # AI red flags
            if email_result["red_flags"]:
                st.markdown('<div class="section-header" style="margin-top:0.75rem;">🚩 AI-Detected Red Flags</div>', unsafe_allow_html=True)
                for flag in email_result["red_flags"]:
                    css = "flag-critical" if email_result["is_phishing"] else "flag-warning"
                    st.markdown(f'<div class="{css}">• {flag}</div>', unsafe_allow_html=True)

            if email_result["explanation"]:
                st.markdown(f'<div class="flag-safe" style="margin-top:0.5rem;">💡 {email_result["explanation"]}</div>', unsafe_allow_html=True)

            st.markdown("---")

        # ── URL Results ───────────────────────────────────────────────────────
        if url_results:
            st.markdown('<div class="section-header">🔗 URL Threat Intelligence</div>', unsafe_allow_html=True)
            for r in url_results:
                if r.get("_telemetry"):   # skip sentinel just in case
                    continue
                short_url = r["url"][:55] + "…" if len(r["url"]) > 55 else r["url"]
                badge_cls = "badge-danger" if r["risk_level"] in ("Critical","High") else ("badge-warn" if r["risk_level"] == "Medium" else "badge-safe")

                with st.expander(f"{r['risk_emoji']} `{short_url}`  — {r['risk_level']}", expanded=r["confirmed_malicious"]):
                    mx1, mx2, mx3 = st.columns(3)
                    mx1.metric("Risk Level", r["risk_level"])
                    mx2.metric("Threat API", "🔴 Hit" if r.get("confirmed_malicious") else "✅ Clean")
                    mx3.metric("HTTPS", "✅" if r["url"].startswith("https://") else "❌")

                    ti = r.get("threat_intel", {})
                    if ti.get("urlhaus") and ti["urlhaus"].get("found"):
                        uh = ti["urlhaus"]
                        st.markdown(f"""
                        <div class="flag-critical">
                        🚨 <b>URLhaus Blacklist Hit</b> — Threat type: <b>{uh['threat']}</b> | Status: <b>{uh['status']}</b>
                        </div>""", unsafe_allow_html=True)

                    if ti.get("virustotal") and ti["virustotal"].get("found") and ti["virustotal"].get("malicious", 0) > 0:
                        vt = ti["virustotal"]
                        st.markdown(f"""
                        <div class="flag-critical">
                        🦠 <b>VirusTotal</b>: {vt['malicious']}/{vt['total']} security engines flagged this URL
                        </div>""", unsafe_allow_html=True)

                    if r["flags"]:
                        st.markdown("<div style='margin-top:0.5rem;'></div>", unsafe_allow_html=True)
                        for flag in r["flags"]:
                            css = "flag-critical" if r["risk_level"] in ("Critical","High") else "flag-warning"
                            st.markdown(f'<div class="{css}">{flag}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="flag-safe">✅ No suspicious patterns detected</div>', unsafe_allow_html=True)

            st.markdown("---")

    # ── AI Security Advisor ───────────────────────────────────────────────────
    if ai_advice:
        st.markdown('<div class="section-header">🤖 AI Security Advisor</div>', unsafe_allow_html=True)

        _sections = ai_advice.get("sections", [])
        _summary  = ai_advice.get("summary", "")

        # Colour & accent per section type
        _section_style = {
            "🔐": ("rgba(234,179,8,0.08)",  "rgba(234,179,8,0.30)"),    # password  – amber
            "📧": ("rgba(239,68,68,0.08)",  "rgba(239,68,68,0.30)"),    # phishing  – red
            "🔗": ("rgba(99,102,241,0.08)", "rgba(99,102,241,0.30)"),   # url       – indigo
        }

        if _sections:
            for sec in _sections:
                _icon = sec["icon"]
                _title = sec["title"]
                _body  = sec["body"]
                _bg, _border = _section_style.get(_icon, ("rgba(14,165,233,0.06)", "rgba(14,165,233,0.25)"))
                st.markdown(f"""
                <div style="background:{_bg}; border:1px solid {_border};
                            border-radius:12px; padding:1rem 1.2rem; margin-bottom:0.75rem;">
                    <div style="font-size:0.72rem; font-weight:700; text-transform:uppercase;
                                letter-spacing:0.1em; color:#94a3b8; margin-bottom:0.5rem;">
                        {_icon}&nbsp; {_title}
                    </div>
                    <div style="font-size:0.88rem; line-height:1.75; color:#cbd5e1;">{_body}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            # Clean scan — show a positive card
            st.markdown("""
            <div style="background:rgba(34,197,94,0.07); border:1px solid rgba(34,197,94,0.25);
                        border-radius:12px; padding:1rem 1.2rem; margin-bottom:0.75rem;">
                <div style="font-size:0.72rem; font-weight:700; text-transform:uppercase;
                            letter-spacing:0.1em; color:#22c55e; margin-bottom:0.5rem;">
                    ✅&nbsp; All Clear
                </div>
                <div style="font-size:0.88rem; line-height:1.75; color:#cbd5e1;">
                    No critical issues detected in this scan. Your digital hygiene looks great!
                </div>
            </div>
            """, unsafe_allow_html=True)

        if _summary:
            st.markdown(f"""
            <div style="background:rgba(14,165,233,0.05); border:1px solid rgba(14,165,233,0.18);
                        border-radius:10px; padding:0.75rem 1.1rem; margin-top:0.25rem;
                        font-size:0.85rem; color:#7dd3fc; font-style:italic;">
                ✨ {_summary}
            </div>
            """, unsafe_allow_html=True)

    # ── Performance Telemetry ─────────────────────────────────────────────────
    st.markdown("<div style='margin-top:1.5rem;'></div>", unsafe_allow_html=True)
    with st.expander(f"Performance Telemetry  —  total scan: {_scan_total_ms} ms", expanded=False):
        st.markdown('<div class="section-header">📊 Per-Component Latency</div>', unsafe_allow_html=True)

        def _lat_bar(label, ms, icon, max_ms=None):
            if max_ms is None:
                max_ms = max(_scan_total_ms, 1)
            pct = min(100, int((ms / max_ms) * 100)) if ms > 0 else 0
            color = "#22c55e" if ms < 300 else ("#eab308" if ms < 1500 else "#ef4444")
            return f"""
            <div style="margin-bottom:0.9rem;">
                <div style="display:flex;justify-content:space-between;font-size:0.8rem;
                            color:#94a3b8;margin-bottom:4px;">
                    <span>{icon} {label}</span>
                    <span style="font-family:'JetBrains Mono',monospace;color:{color};
                                 font-weight:600;">{ms} ms</span>
                </div>
                <div style="background:rgba(255,255,255,0.06);border-radius:4px;height:7px;">
                    <div style="width:{pct}%;height:100%;background:{color};
                                border-radius:4px;transition:width 0.6s;"></div>
                </div>
            </div>"""

        bars_html = ""
        if password_input:
            bars_html += _lat_bar("Password Check (zxcvbn)", _pw_ms, "🔐")
        if email_input:
            bars_html += _lat_bar("NLP Phishing Scorer", _nlp_ms, "🧠")
            bars_html += _lat_bar("Gemini AI Analysis", _ai_ms, "🤖")
            bars_html += _lat_bar("ML Classifier (sklearn)", _ml_ms, "🔬")
        if url_input:
            bars_html += _lat_bar("URL Scan (total)", _url_ms, "🔗")
        bars_html += _lat_bar("Total Scan Time", _scan_total_ms, "⏱️")
        st.markdown(bars_html, unsafe_allow_html=True)

        # ── Parallel Speedup (only shown when 2+ tasks were active) ───────────
        _active_tasks = sum([bool(password_input), bool(email_input), bool(url_input)])
        if _active_tasks >= 2:
            wall_ms = max(_scan_total_ms, 1)
            seq_ms  = _sequential_estimate_ms
            # Cap speedup at 1.0 minimum so thread-pool overhead never shows as slowdown
            speedup = round(max(seq_ms / wall_ms, 1.0), 2)
            _saved_ms = max(0, seq_ms - wall_ms)

            sp_color = "#22c55e" if speedup >= 1.5 else ("#eab308" if speedup >= 1.1 else "#94a3b8")
            sp_label = "🚀 Significant" if speedup >= 1.5 else ("✅ Moderate" if speedup >= 1.1 else "✅ Efficient")

            st.markdown("<hr style='border-color:rgba(56,189,248,0.1);margin:0.75rem 0;'>",
                        unsafe_allow_html=True)
            st.markdown('<div class="section-header">⚡ Parallel Speedup</div>',
                        unsafe_allow_html=True)

            sp_c1, sp_c2, sp_c3 = st.columns(3)
            sp_c1.metric("Wall-clock Time", f"{_scan_total_ms} ms",
                         help="Actual elapsed time — all tasks ran in parallel")
            sp_c2.metric("Sequential Estimate", f"{seq_ms} ms",
                         help="Sum of individual task times — what sequential would cost")
            sp_c3.metric("Parallel Speedup", f"{speedup}×",
                         help="sequential_estimate ÷ wall_time  (≥1 means no slowdown)")

            st.markdown(f"""
            <div style="margin-top:0.6rem;background:rgba(255,255,255,0.03);
                        border:1px solid rgba(56,189,248,0.12);border-radius:10px;
                        padding:0.75rem 1rem;font-size:0.82rem;color:#94a3b8;">
                <b style="color:#e2e8f0">{_active_tasks} scan module{'s' if _active_tasks>1 else ''}</b>
                ran simultaneously (ThreadPoolExecutor · 4 workers).
                Saved approximately <b style="color:{sp_color}">{_saved_ms} ms</b>
                vs sequential. Speedup: <b style="color:{sp_color};font-weight:700">{speedup}×</b>
                &nbsp;<span style="color:{sp_color};font-weight:700">{sp_label}</span>
            </div>
            """, unsafe_allow_html=True)

            # Per-URL timing breakdown (if applicable)
            if _url_telemetry and _url_telemetry.get("url_count", 0) > 0:
                st.markdown("<div style='margin-top:0.75rem;'></div>", unsafe_allow_html=True)
                st.markdown('<div class="section-header">🔍 Per-URL API Timing</div>',
                            unsafe_allow_html=True)
                rows = ""
                for r in url_results:
                    tm = r.get("timing", {})
                    short = r["url"][:40] + "…" if len(r["url"]) > 40 else r["url"]
                    uh_ms = tm.get("urlhaus_ms", 0)
                    vt_ms = tm.get("virustotal_ms", 0)
                    tot_ms = tm.get("total_ms", 0)
                    rows += f"""
                    <div style="margin-bottom:0.5rem;background:rgba(255,255,255,0.02);
                                border:1px solid rgba(56,189,248,0.08);border-radius:8px;
                                padding:0.5rem 0.75rem;">
                        <div style="font-size:0.78rem;color:#7dd3fc;margin-bottom:0.3rem;
                                    font-family:'JetBrains Mono',monospace;">{short}</div>
                        <div style="display:flex;gap:1.5rem;font-size:0.75rem;color:#64748b;">
                            <span>URLhaus: <b style="color:#94a3b8">{uh_ms} ms</b></span>
                            <span>VirusTotal: <b style="color:#94a3b8">{vt_ms} ms</b></span>
                            <span>Total: <b style="color:#e2e8f0">{tot_ms} ms</b></span>
                        </div>
                    </div>"""
                st.markdown(rows, unsafe_allow_html=True)


# ─── Footer ───────────────────────────────────────────────────────────────────
st.markdown("<div style='margin-top:3rem;'></div>", unsafe_allow_html=True)
st.markdown("""
<div style="text-align:center; padding:1.5rem; border-top:1px solid rgba(56,189,248,0.1);">
    <div style="font-size:0.75rem; color:#334155; letter-spacing:0.05em;">
        🛡️ <b style="color:#475569">AI CyberShield</b> &nbsp;|&nbsp;
        Powered by <b style="color:#475569">Gemini AI</b> · <b style="color:#475569">URLhaus</b> · <b style="color:#475569">zxcvbn</b>
        &nbsp;|&nbsp; Hackathon 2026
    </div>
</div>
""", unsafe_allow_html=True)
