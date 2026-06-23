import streamlit as st
import plotly.graph_objects as go
from datetime import datetime
from modules.password_checker import check_password_strength
from modules.url_analyzer import analyze_url_risk
from modules.email_detector import analyze_email_content

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="CyberShield AI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- MODERN BALANCED CYBER STYLE ---
st.markdown("""
    <style>
    /* Dark background with crisp typography */
    .stApp {
        background-color: #0F172A;
        color: #F1F5F9;
    }

    /* Clean Title styling description */
    .cyber-subtitle {
        color: #94A3B8;
        font-size: 1rem;
        margin-bottom: 1.5rem;
        margin-top: -1rem;
    }

    /* Solid borders for info containers */
    div[data-testid="stContainer"] {
        background-color: #1E293B !important;
        border: 1px solid #334155 !important;
        border-radius: 12px !important;
        padding: 10px;
    }

    /* Input Fields styling */
    div[data-baseweb="input"], div[data-baseweb="textarea"] {
        background-color: #0F172A !important;
        border: 1px solid #475569 !important;
        border-radius: 8px !important;
    }
    div[data-baseweb="input"]:focus-within, div[data-baseweb="textarea"]:focus-within {
        border-color: #3B82F6 !important;
    }
    input, textarea {
        color: #F8FAFC !important;
    }

    /* ── NEW: Threat level badge in sidebar ── */
    .threat-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-top: 6px;
        margin-bottom: 2px;
    }
    .badge-secure   { background: #052e16; color: #4ade80; border: 1px solid #166534; }
    .badge-guarded  { background: #1c1917; color: #fbbf24; border: 1px solid #92400e; }
    .badge-elevated { background: #2d1515; color: #f87171; border: 1px solid #991b1b; }
    .badge-critical { background: #1a0a0a; color: #ef4444; border: 1px solid #7f1d1d;
                      animation: pulse-red 1.4s ease-in-out infinite; }
    @keyframes pulse-red {
        0%, 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0.5); }
        50%       { box-shadow: 0 0 0 6px rgba(239,68,68,0); }
    }

    /* ── NEW: Scan counter pills next to nav labels ── */
    .nav-pill {
        display: inline-block;
        background: #1E3A5F;
        color: #60A5FA;
        border-radius: 999px;
        font-size: 0.68rem;
        font-weight: 700;
        padding: 1px 7px;
        margin-left: 6px;
        vertical-align: middle;
    }

    /* ── NEW: Scan history log rows ── */
    .log-row {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 6px 0;
        border-bottom: 1px solid #1E293B;
        font-size: 0.82rem;
        font-family: 'Courier New', monospace;
    }
    .log-row:last-child { border-bottom: none; }
    .log-ts   { color: #475569; min-width: 72px; }
    .log-type { font-weight: 700; min-width: 48px; }
    .log-safe     { color: #4ade80; }
    .log-warn     { color: #fbbf24; }
    .log-danger   { color: #f87171; }

    /* ── NEW: Entropy advisory chip ── */
    .entropy-chip {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-top: 6px;
    }
    .entropy-low  { background: #2d1515; color: #f87171; border: 1px solid #7f1d1d; }
    .entropy-mid  { background: #1c1917; color: #fbbf24; border: 1px solid #92400e; }
    .entropy-high { background: #052e16; color: #4ade80; border: 1px solid #166534; }
    </style>
""", unsafe_allow_html=True)


# ── HELPER: derive threat level from session state ──────────────────────────
def _threat_level(threats: int) -> tuple[str, str]:
    """Returns (label, css_class) for the sidebar badge."""
    if threats == 0:
        return "SECURE", "badge-secure"
    elif threats == 1:
        return "GUARDED", "badge-guarded"
    elif threats <= 3:
        return "ELEVATED", "badge-elevated"
    else:
        return "CRITICAL", "badge-critical"


# ── HELPER: append a scan event to rolling history (last 8 entries) ─────────
def _log_event(scan_type: str, label: str, verdict: str, css_class: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    entry = {
        "ts": ts,
        "type": scan_type,
        "label": label,
        "verdict": verdict,
        "css": css_class,
    }
    st.session_state.scan_history.insert(0, entry)
    st.session_state.scan_history = st.session_state.scan_history[:8]


# ── HELPER: render entropy advisory chip ────────────────────────────────────
def _entropy_chip(bits: float) -> None:
    if bits < 40:
        st.markdown(
            "<span class='entropy-chip entropy-low'>"
            f"⚠️ {bits} bits — weak density, vulnerable to dictionary attacks"
            "</span>",
            unsafe_allow_html=True,
        )
    elif bits < 60:
        st.markdown(
            "<span class='entropy-chip entropy-mid'>"
            f"⚡ {bits} bits — moderate, exposed to optimised cluster cracking"
            "</span>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            "<span class='entropy-chip entropy-high'>"
            f"✅ {bits} bits — strong distribution, brute-force resistant"
            "</span>",
            unsafe_allow_html=True,
        )


# --- SESSION STATE INITIALISATION ---
_defaults = {
    "total_scans":    0,
    "threats_blocked": 0,
    "pwd_scans":      0,
    "url_scans":      0,
    "email_scans":    0,
    "scan_history":   [],        # NEW: rolling event log
}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ CyberShield AI")
    st.caption("Intelligent Digital Safety Platform")

    # ── NEW: animated threat level badge ──
    threat_label, threat_css = _threat_level(st.session_state.threats_blocked)
    st.markdown(
        f"<div class='threat-badge {threat_css}'>{threat_label}</div>",
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # ── NEW: nav labels with live scan-count pills ──
    def _nav_label(name: str, count: int) -> str:
        pill = f"<span class='nav-pill'>{count}</span>" if count > 0 else ""
        return f"{name}{pill}"

    menu_choice = st.radio(
        "Navigation Menu",
        ["Dashboard", "Password Analyzer", "URL Analyzer", "Email Detector"],
        format_func=lambda x: x,   # labels rendered separately below
    )

    # Render pill annotations beneath the radio (Streamlit radio captions)
    st.markdown(
        f"""
        <div style='font-size:0.75rem; color:#475569; line-height:2.2; margin-top:-8px;'>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Password&nbsp;
            {f"<span class='nav-pill'>{st.session_state.pwd_scans}</span>" if st.session_state.pwd_scans else ""}
        <br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;URL&nbsp;
            {f"<span class='nav-pill'>{st.session_state.url_scans}</span>" if st.session_state.url_scans else ""}
        <br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Email&nbsp;
            {f"<span class='nav-pill'>{st.session_state.email_scans}</span>" if st.session_state.email_scans else ""}
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # ── NEW: sidebar mini scan-history terminal ──
    st.markdown(
        "<p style='font-size:0.78rem; color:#64748B; font-weight:600;"
        " letter-spacing:0.06em; text-transform:uppercase; margin-bottom:6px;'>"
        "Recent Activity</p>",
        unsafe_allow_html=True,
    )
    if not st.session_state.scan_history:
        st.caption("No scans yet this session.")
    else:
        rows_html = "".join(
            f"<div class='log-row'>"
            f"<span class='log-ts'>{e['ts']}</span>"
            f"<span class='log-type {e['css']}'>{e['type']}</span>"
            f"<span style='color:#CBD5E1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;'>{e['label'][:22]}</span>"
            f"</div>"
            for e in st.session_state.scan_history
        )
        st.markdown(
            f"<div style='background:#0F172A; border-radius:8px; padding:8px 10px;'>{rows_html}</div>",
            unsafe_allow_html=True,
        )

    # ── NEW: reset session button ──
    st.markdown("---")
    if st.button("🔄 Reset Session", use_container_width=True):
        for k, v in _defaults.items():
            st.session_state[k] = v if not isinstance(v, list) else []
        # clear per-scan dedup keys
        dedup_keys = [k for k in st.session_state if k.startswith(("pwd_flag_", "url_flag_", "email_flag_", "last_"))]
        for k in dedup_keys:
            del st.session_state[k]
        st.rerun()


# =============================================================================
# 1. DASHBOARD
# =============================================================================
if menu_choice == "Dashboard":
    st.title("📊 Security Command Center")
    st.markdown(
        "<div class='cyber-subtitle'>Real-time session security indicators and processed threat logs.</div>",
        unsafe_allow_html=True,
    )

    col_m1, col_m2, col_m3 = st.columns(3)
    with col_m1:
        st.metric(label="Total Ecosystem Scans", value=st.session_state.total_scans)
    with col_m2:
        # FIX: removed artificial 45% floor — score now reflects real session state
        threats = st.session_state.threats_blocked
        total   = max(st.session_state.total_scans, 1)
        safety_score = max(round(100 - (threats / total) * 100), 0)
        delta_color = "normal" if safety_score >= 70 else "inverse"
        st.metric(
            label="System Security Index",
            value=f"{safety_score}%",
            delta=f"{threats} threat(s) detected",
            delta_color=delta_color,
        )
    with col_m3:
        st.metric(label="Identified Threats Flagged", value=st.session_state.threats_blocked)

    st.markdown("<br>", unsafe_allow_html=True)
    col_g1, col_g2 = st.columns([1.5, 1], gap="medium")

    with col_g1:
        with st.container(border=True):
            st.markdown("#### Operational Telemetry Log")
            fig = go.Figure(data=[go.Bar(
                x=["Credentials Checked", "URLs Analyzed", "Phishing Emails"],
                y=[
                    st.session_state.pwd_scans,
                    st.session_state.url_scans,
                    st.session_state.email_scans,
                ],
                marker_color=["#3B82F6", "#F59E0B", "#EF4444"],
                width=0.4,
            )])
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#94A3B8", height=250,
                margin=dict(l=10, r=10, t=10, b=10),
                yaxis=dict(gridcolor="#334155", zeroline=False),
            )
            st.plotly_chart(fig, use_container_width=True)

    with col_g2:
        with st.container(border=True):
            st.markdown("#### Real-time Scanner Feed")
            if st.session_state.total_scans == 0:
                st.info("📡 Scanner feed idling. Perform a security check to generate data log streams.")
            else:
                st.success(
                    f"✔️ Active Protection On. "
                    f"Logged {st.session_state.total_scans} event(s) this session."
                )

        # ── NEW: full scan history table on dashboard ──
        st.markdown("<br>", unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown("#### Session Event Log")
            if not st.session_state.scan_history:
                st.caption("No events logged yet.")
            else:
                def _row_html(e: dict) -> str:
                    verdict_color = "color:#f87171" if "THREAT" in e["verdict"] else "color:#4ade80"
                    return (
                        f"<div class='log-row'>"
                        f"<span class='log-ts'>{e['ts']}</span>"
                        f"<span class='log-type {e['css']}'>{e['type']}</span>"
                        f"<span style='color:#CBD5E1;'>{e['label']}</span>"
                        f"<span style='margin-left:auto; font-size:0.75rem; {verdict_color}'>"
                        f"{e['verdict']}</span>"
                        f"</div>"
                    )
                rows_html = "".join(_row_html(e) for e in st.session_state.scan_history)
                st.markdown(
                    f"<div style='background:#0F172A; border-radius:8px; padding:10px 14px;'>{rows_html}</div>",
                    unsafe_allow_html=True,
                )


# =============================================================================
# 2. PASSWORD ANALYZER
# =============================================================================
elif menu_choice == "Password Analyzer":
    st.title("🔐 Password Strength Analyzer")
    st.markdown(
        "<div class='cyber-subtitle'>Evaluate credential resilience using Shannon entropy mappings and safety check criteria.</div>",
        unsafe_allow_html=True,
    )

    with st.container(border=True):
        password_input = st.text_input(
            "Enter a password string to analyze:",
            type="password",
            placeholder="Type password profile here...",
        )

    if password_input:
        # ── dedup: only count a genuinely new password ──
        if "last_pwd" not in st.session_state or st.session_state.last_pwd != password_input:
            st.session_state.total_scans += 1
            st.session_state.pwd_scans   += 1
            st.session_state.last_pwd     = password_input

        res = check_password_strength(password_input)

        if res["category"] in ["Weak", "Medium"] and f"pwd_flag_{password_input}" not in st.session_state:
            st.session_state.threats_blocked += 1
            st.session_state[f"pwd_flag_{password_input}"] = True
            _log_event("PWD", password_input[:14] + "…" if len(password_input) > 14 else password_input,
                       "⚠️ THREAT — weak credential", "log-warn")
        else:
            _log_event("PWD", password_input[:14] + "…" if len(password_input) > 14 else password_input,
                       "✔ CLEAN", "log-safe")

        st.markdown("### 📊 Assessment Report")
        col1, col2 = st.columns([1, 1.2], gap="large")

        with col1:
            with st.container(border=True):
                st.markdown("#### Analysis Metrics")
                if res["category"] == "Strong":
                    st.success(f"🟢 Category: {res['category'].upper()}")
                elif res["category"] == "Medium":
                    st.warning(f"🟡 Category: {res['category'].upper()}")
                else:
                    st.error(f"🔴 Category: {res['category'].upper()}")

                st.markdown("<br>", unsafe_allow_html=True)
                st.progress(res["score"] / 5.0, text=f"Security Score: {res['score']}/5")
                st.metric(label="Calculated Password Entropy", value=f"{res['entropy']} bits")

                # FIX: restored entropy advisory (was stripped in active version)
                _entropy_chip(res["entropy"])

        with col2:
            with st.container(border=True):
                st.markdown("#### Complexity Breakdown")
                st.checkbox("Meets standard baseline length (≥ 8 chars)", value=(res["length"] >= 8), disabled=True)
                st.checkbox("Contains uppercase letters (A–Z)",           value=res["has_upper"],  disabled=True)
                st.checkbox("Contains lowercase letters (a–z)",           value=res["has_lower"],  disabled=True)
                st.checkbox("Contains numeric characters (0–9)",          value=res["has_digits"], disabled=True)
                st.checkbox("Contains special character indicators (!, @, #, $…)",
                            value=res["has_special"], disabled=True)

            st.markdown("<br>", unsafe_allow_html=True)
            with st.container(border=True):
                st.markdown("#### Improvement Recommendations")
                for tip in res["feedback"]:
                    st.markdown(tip)

        # ── NEW: copy-friendly result summary ──
        with st.expander("📋 Export Assessment Summary"):
            summary = (
                f"CyberShield AI — Password Assessment\n"
                f"{'─'*38}\n"
                f"Category   : {res['category']}\n"
                f"Score      : {res['score']}/5\n"
                f"Entropy    : {res['entropy']} bits\n"
                f"Length     : {res['length']} chars\n"
                f"Uppercase  : {'✔' if res['has_upper']   else '✘'}\n"
                f"Lowercase  : {'✔' if res['has_lower']   else '✘'}\n"
                f"Digits     : {'✔' if res['has_digits']  else '✘'}\n"
                f"Special    : {'✔' if res['has_special'] else '✘'}\n"
                f"\nRecommendations:\n"
                + "\n".join(f"  {t}" for t in res["feedback"])
            )
            st.code(summary, language="text")


# =============================================================================
# 3. URL ANALYZER
# =============================================================================
elif menu_choice == "URL Analyzer":
    st.title("🌐 URL Risk Analyzer")
    st.markdown(
        "<div class='cyber-subtitle'>Scan domain pointers and address syntax for common fraud patterns.</div>",
        unsafe_allow_html=True,
    )

    with st.container(border=True):
        url_input = st.text_input(
            "Enter target URL address payload:",
            placeholder="example-secure-login.com/verify",
        )

    if url_input:
        if "last_url" not in st.session_state or st.session_state.last_url != url_input:
            st.session_state.total_scans += 1
            st.session_state.url_scans   += 1
            st.session_state.last_url     = url_input

        res = analyze_url_risk(url_input)

        if res["classification"] in ["Suspicious", "Dangerous"] and f"url_flag_{url_input}" not in st.session_state:
            st.session_state.threats_blocked += 1
            st.session_state[f"url_flag_{url_input}"] = True
            verdict_label = "⚠️ THREAT — " + res["classification"].upper()
            log_css = "log-danger" if res["classification"] == "Dangerous" else "log-warn"
        else:
            verdict_label = "✔ CLEAN"
            log_css = "log-safe"

        _log_event("URL", url_input[:28] + "…" if len(url_input) > 28 else url_input, verdict_label, log_css)

        st.markdown("### 📊 Scan Summary")
        col1, col2 = st.columns([1, 1.2], gap="large")

        with col1:
            with st.container(border=True):
                st.markdown("#### Threat Metrics")
                if res["classification"] == "Safe":
                    st.success(f"🟢 Verdict: {res['classification'].upper()}")
                elif res["classification"] == "Suspicious":
                    st.warning(f"🟡 Verdict: {res['classification'].upper()}")
                else:
                    st.error(f"🔴 Verdict: {res['classification'].upper()}")

                st.markdown("<br>", unsafe_allow_html=True)
                st.progress(res["risk_score"] / 100.0, text=f"Calculated Risk Score: {res['risk_score']}%")

                st.markdown("---")
                st.markdown("**Structural Metadata:**")
                st.markdown(f"• URL Character Count: `{res['length']}`")
                st.markdown(f"• Domain Dot Separation: `{res['dots']}`")
                st.markdown(f"• Contains Direct IP Route: `{res['has_ip']}`")

        with col2:
            with st.container(border=True):
                st.markdown("#### Identified Risks & Reasons")
                for reason in res["reasons"]:
                    st.markdown(reason)

        # ── NEW: export summary ──
        with st.expander("📋 Export Scan Summary"):
            summary = (
                f"CyberShield AI — URL Scan Report\n"
                f"{'─'*38}\n"
                f"URL        : {url_input}\n"
                f"Verdict    : {res['classification']}\n"
                f"Risk Score : {res['risk_score']}%\n"
                f"Length     : {res['length']}\n"
                f"Dot Count  : {res['dots']}\n"
                f"IP Route   : {res['has_ip']}\n"
                f"\nRisk Reasons:\n"
                + "\n".join(f"  {r}" for r in res["reasons"])
            )
            st.code(summary, language="text")


# =============================================================================
# 4. EMAIL DETECTOR
# =============================================================================
elif menu_choice == "Email Detector":
    st.title("📧 Phishing Email Detector")
    st.markdown(
        "<div class='cyber-subtitle'>Analyze message copy against trained machine learning vector matrices.</div>",
        unsafe_allow_html=True,
    )

    with st.container(border=True):
        email_input = st.text_area(
            "Paste email message content payload:",
            placeholder="Paste text here...",
            height=140,
        )

    if email_input:
        if "last_email" not in st.session_state or st.session_state.last_email != email_input:
            st.session_state.total_scans  += 1
            st.session_state.email_scans  += 1
            st.session_state.last_email    = email_input

        res = analyze_email_content(email_input)

        _email_key = f"email_flag_{hash(email_input)}"
        if res["verdict"] == "Phishing" and _email_key not in st.session_state:
            st.session_state.threats_blocked += 1
            st.session_state[_email_key] = True
            _log_event("EMAIL", email_input[:24].replace("\n", " ") + "…", "⚠️ THREAT — PHISHING", "log-danger")
        else:
            _log_event("EMAIL", email_input[:24].replace("\n", " ") + "…", "✔ CLEAN", "log-safe")

        st.markdown("### 📊 Evaluation Report")
        col1, col2 = st.columns([1, 1.2], gap="large")

        with col1:
            with st.container(border=True):
                st.markdown("#### Classification Metrics")
                if res["verdict"] == "Phishing":
                    st.error(f"🚨 Verdict: {res['verdict'].upper()} DETECTED")
                else:
                    st.success(f"🟢 Verdict: CLEAN ({res['verdict'].upper()})")

                st.markdown("<br>", unsafe_allow_html=True)
                st.progress(
                    res["confidence"] / 100.0,
                    text=f"ML Classifier Confidence: {res['confidence']}%",
                )

                # ── NEW: confidence advisory ──
                if res["confidence"] < 60:
                    st.caption("ℹ️ Low confidence — edge-case input or ambiguous signals.")
                elif res["confidence"] < 85:
                    st.caption("⚡ Moderate confidence — treat with caution.")
                else:
                    st.caption("✅ High confidence — strong signal from classifier.")

        with col2:
            with st.container(border=True):
                st.markdown("#### High-Risk Text Patterns Caught")
                if res["triggers"]:
                    for trigger in res["triggers"]:
                        st.markdown(trigger)
                else:
                    st.markdown(
                        "<span style='color:#4ade80; font-size:0.9rem;'>"
                        "✔ No high-risk language patterns detected.</span>",
                        unsafe_allow_html=True,
                    )

        # ── NEW: export summary ──
        with st.expander("📋 Export Detection Report"):
            summary = (
                f"CyberShield AI — Email Detection Report\n"
                f"{'─'*38}\n"
                f"Verdict    : {res['verdict']}\n"
                f"Confidence : {res['confidence']}%\n"
                f"\nTriggered Patterns:\n"
                + ("\n".join(f"  {t}" for t in res["triggers"]) if res["triggers"] else "  None")
                + f"\n\nScanned Content (first 200 chars):\n  {email_input[:200]}"
            )
            st.code(summary, language="text")