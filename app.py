import streamlit as st
import plotly.graph_objects as go
from modules.password_checker import check_password_strength

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- MODERN CYBERPUNK CSS OVERHAUL ---
st.markdown("""
    <style>
    .stApp {
        background-color: #0B0F19;
    }
    
    /* Fixed Title System - Separates Emoji from Gradient Text to prevent rendering bugs */
    .title-container {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 0.5rem;
    }
    .title-emoji {
        font-size: 2.5rem;
    }
    .cyber-title {
        font-size: 2.5rem;
        font-weight: 800;
        background: linear-gradient(90deg, #3B82F6, #10B981);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .cyber-subtitle {
        color: #94A3B8;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    
    /* Input field overrides */
    div[data-baseweb="input"] {
        background-color: #1E293B !important;
        border: 1px solid #334155 !important;
        border-radius: 8px !important;
    }
    div[data-baseweb="input"]:focus-within {
        border-color: #3B82F6 !important;
        box-shadow: 0 0 0 1px #3B82F6 !important;
    }
    input {
        color: #F8FAFC !important;
    }
    </style>
""", unsafe_allow_html=True)

# --- SIDEBAR NAVIGATION ---
with st.sidebar:
    st.markdown("<h2 style='color: #3B82F6; margin-bottom: 0;'>🛡️ CyberShield AI</h2>", unsafe_allow_html=True)
    st.caption("Intelligent Digital Safety Platform")
    st.markdown("---")
    
    menu_choice = st.radio(
        "Navigation Menu",
        ["Dashboard", "Password Analyzer", "URL Analyzer", "Email Detector", "About"],
        label_visibility="collapsed"
    )

# --- SESSION STATE TRACKING ---
if 'total_scans' not in st.session_state:
    st.session_state.total_scans = 0
if 'threats_blocked' not in st.session_state:
    st.session_state.threats_blocked = 0

# --- APP ROUTING ---

# 1. DASHBOARD VIEW (FIXED & HYPED UP)
if menu_choice == "Dashboard":
    # Solved the rendering issue shown in image_288cd8.png here by splitting the emoji out of the gradient CSS class
    st.markdown("""
        <div class='title-container'>
            <span class='title-emoji'>📊</span>
            <span class='cyber-title'>Security Command Center</span>
        </div>
    """, unsafe_allow_html=True)
    st.markdown("<div class='cyber-subtitle'>Real-time data risk assessments, heuristic logs, and active threat telemetry.</div>", unsafe_allow_html=True)
    
    # Real-time Metrics Matrix
    col_m1, col_m2, col_m3 = st.columns(3)
    with col_m1:
        with st.container(border=True):
            st.metric(label="Total Ecosystem Scans", value=st.session_state.total_scans, delta="Active Session")
    with col_m2:
        with st.container(border=True):
            # Baseline safety rating drops slightly as user scans unsafe stuff
            safety_score = max(100 - (st.session_state.threats_blocked * 15), 50)
            st.metric(label="System Security Index", value=f"{safety_score}%", delta="-0.0%" if st.session_state.threats_blocked == 0 else "-Threat Verified")
    with col_m3:
        with st.container(border=True):
            st.metric(label="Identified Threats Flagged", value=st.session_state.threats_blocked, delta="Action Required" if st.session_state.threats_blocked > 0 else "System Clear")

    st.markdown("<br>", unsafe_allow_html=True)
    
    # Dashboard Grid Visualizations
    col_g1, col_g2 = st.columns([1.5, 1], gap="medium")
    
    with col_g1:
        with st.container(border=True):
            st.markdown("#### Operational Telemetry Log")
            
            # Simple Plotly Chart tracking threat categories checked
            categories = ['Credentials', 'Malicious URLs', 'Phishing Attempts']
            counts = [st.session_state.total_scans, 0, 0] # Will dynamically increase as we add modules
            
            fig = go.Figure(data=[go.Bar(
                x=categories, y=counts,
                marker_color=['#3B82F6', '#F59E0B', '#EF4444'],
                text=counts, textposition='auto'
            )])
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color='#94A3B8',
                height=300,
                margin=dict(l=20, r=20, t=20, b=20)
            )
            st.plotly_chart(fig, use_container_width=True)

    with col_g2:
        with st.container(border=True):
            st.markdown("#### Real-time Scanner Feed")
            if st.session_state.total_scans == 0:
                st.info("📡 Feed idling. No telemetry files parsed during this session yet.")
            else:
                st.success(f"✔️ Core engine executed successfully. logged {st.session_state.total_scans} interaction(s).")

# 2. PASSWORD ANALYZER VIEW
elif menu_choice == "Password Analyzer":
    st.markdown("""
        <div class='title-container'>
            <span class='title-emoji'>🔐</span>
            <span class='cyber-title'>Password Strength Analyzer</span>
        </div>
    """, unsafe_allow_html=True)
    st.markdown("<div class='cyber-subtitle'>Evaluate credential strength using Shannon entropy mappings and security heuristics.</div>", unsafe_allow_html=True)
    
    with st.container(border=True):
        password_input = st.text_input(
            "Analyze Threat Profile of Credential String:", 
            type="password", 
            placeholder="Type or paste a password string to test security profile..."
        )

    if password_input:
        if 'last_password' not in st.session_state or st.session_state.last_password != password_input:
            st.session_state.total_scans += 1
            st.session_state.last_password = password_input
            
        result = check_password_strength(password_input)
        
        if result['category'] in ["Weak", "Medium"] and 'flagged_pass' not in st.session_state:
            st.session_state.threats_blocked += 1
            
        st.markdown("### 📊 Assessment Report")
        col1, col2 = st.columns([1, 1.2], gap="large")
        
        with col1:
            with st.container(border=True):
                st.markdown("#### Core Threat Metrics")
                if result['category'] == "Strong":
                    st.success(f"⚡ Status: SECURE SYSTEM FLAG ({result['category'].upper()})")
                elif result['category'] == "Medium":
                    st.warning(f"⚠️ Status: WARNING FLAG ({result['category'].upper()})")
                else:
                    st.error(f"🚨 Status: CRITICAL BREACH RISK ({result['category'].upper()})")
                
                st.markdown("<br>", unsafe_allow_html=True)
                st.progress(result['score'] / 5.0, text=f"Calculated Score Matrix: {result['score']}/5")
                st.markdown("---")
                st.metric(label="Shannon Entropy Rating", value=f"{result['entropy']} Bits")
                
                if result['entropy'] < 40:
                    st.error("❌ **Critical Entropy:** Instant structural collapse against modern multi-threaded attacks.")
                elif result['entropy'] < 60:
                    st.warning("⚠️ **Moderate Entropy:** Susceptible to GPU-accelerated brute-forcing.")
                else:
                    st.success("✅ **High Entropy:** Excellent random-spread resilience.")

        with col2:
            with st.container(border=True):
                st.markdown("#### Complexity Heuristics")
                st.checkbox("Meets standard baseline length (≥ 8 chars)", value=(result['length'] >= 8), disabled=True)
                st.checkbox("Contains upper-case register (A-Z)", value=result['has_upper'], disabled=True)
                st.checkbox("Contains lower-case register (a-z)", value=result['has_lower'], disabled=True)
                st.checkbox("Contains numeric sequence (0-9)", value=result['has_digits'], disabled=True)
                st.checkbox("Contains special symbolic characters", value=result['has_special'], disabled=True)
            
            st.markdown("<br>", unsafe_allow_html=True)
            with st.container(border=True):
                st.markdown("#### System Remediation Steps")
                for tip in result['feedback']:
                    st.markdown(tip)

# OTHER TEMPLATE VIEWS REMAIN INTENTIONALLY UNTOUCHED UNTIL EXTENDED
elif menu_choice == "URL Analyzer":
    st.markdown("<div class='title-container'><span class='title-emoji'>🌐</span><span class='cyber-title'>URL Risk Analyzer</span></div>", unsafe_allow_html=True)
    st.info("URL vector parser interface incoming in the next patch iteration.")

elif menu_choice == "Email Detector":
    st.markdown("<div class='title-container'><span class='title-emoji'>📧</span><span class='cyber-title'>Phishing Email Detector</span></div>", unsafe_allow_html=True)
    st.info("AI/ML Phishing prediction matrices incoming in the next patch iteration.")

elif menu_choice == "About":
    st.markdown("<div class='title-container'><span class='title-emoji'>📋</span><span class='cyber-title'>Operations Profile</span></div>", unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown("**CyberShield AI** is an unified tactical security dashboard built for the CyberCoders Hackathon.")