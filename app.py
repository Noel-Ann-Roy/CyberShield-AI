# import streamlit as st
# import plotly.graph_objects as go
# from modules.password_checker import check_password_strength
# from modules.url_analyzer import analyze_url_risk
# from modules.email_detector import analyze_email_content

# # --- PAGE CONFIGURATION ---
# st.set_page_config(
#     page_title="CyberShield AI Dashboard",
#     page_icon="🛡️",
#     layout="wide",
#     initial_sidebar_state="expanded"
# )

# # --- MODERN BALANCED CYBER STYLE ---
# st.markdown("""
#     <style>
#     /* Dark background with crisp typography */
#     .stApp {
#         background-color: #0F172A;
#         color: #F1F5F9;
#     }
    
#     /* Clean Title formatting */
#     .cyber-title {
#         font-size: 2.2rem;
#         font-weight: 800;
#         background: linear-gradient(90deg, #3B82F6, #10B981);
#         -webkit-background-clip: text;
#         -webkit-text-fill-color: transparent;
#         margin-bottom: 0.2rem;
#     }
    
#     .cyber-subtitle {
#         color: #94A3B8;
#         font-size: 1rem;
#         margin-bottom: 1.5rem;
#     }
    
#     /* Solid borders for info containers */
#     div[data-testid="stContainer"] {
#         background-color: #1E293B !important;
#         border: 1px solid #334155 !important;
#         border-radius: 12px !important;
#         padding: 10px;
#     }

#     /* Input Fields styling */
#     div[data-baseweb="input"], div[data-baseweb="textarea"] {
#         background-color: #0F172A !important;
#         border: 1px solid #475569 !important;
#         border-radius: 8px !important;
#     }
#     div[data-baseweb="input"]:focus-within, div[data-baseweb="textarea"]:focus-within {
#         border-color: #3B82F6 !important;
#     }
#     input, textarea {
#         color: #F8FAFC !important;
#     }
#     </style>
# """, unsafe_allow_html=True)

# # --- SESSION STATES ---
# if 'total_scans' not in st.session_state: st.session_state.total_scans = 0
# if 'threats_blocked' not in st.session_state: st.session_state.threats_blocked = 0
# if 'pwd_scans' not in st.session_state: st.session_state.pwd_scans = 0
# if 'url_scans' not in st.session_state: st.session_state.url_scans = 0
# if 'email_scans' not in st.session_state: st.session_state.email_scans = 0

# # --- SIDEBAR NAV ---
# with st.sidebar:
#     st.markdown("<h2 style='color: #3B82F6; margin-bottom: 0;'>🛡️ CyberShield AI</h2>", unsafe_allow_html=True)
#     st.caption("Intelligent Digital Safety Platform")
#     st.markdown("---")
#     menu_choice = st.radio("Navigation Menu", ["Dashboard", "Password Analyzer", "URL Analyzer", "Email Detector"])

# # --- CORE SUBSYSTEM ROUTING ---

# # 1. DASHBOARD
# if menu_choice == "Dashboard":
#     st.markdown("<div class='cyber-title'>📊 Security Command Center</div>", unsafe_allow_html=True)
#     st.markdown("<div class='cyber-subtitle'>Real-time session security indicators and processed threat logs.</div>", unsafe_allow_html=True)
    
#     col_m1, col_m2, col_m3 = st.columns(3)
#     with col_m1:
#         st.metric(label="Total Ecosystem Scans", value=st.session_state.total_scans)
#     with col_m2:
#         safety_score = max(100 - (st.session_state.threats_blocked * 15), 45)
#         st.metric(label="System Security Index", value=f"{safety_score}%")
#     with col_m3:
#         st.metric(label="Identified Threats Flagged", value=st.session_state.threats_blocked)

#     st.markdown("<br>", unsafe_allow_html=True)
#     col_g1, col_g2 = st.columns([1.5, 1], gap="medium")
    
#     with col_g1:
#         with st.container(border=True):
#             st.markdown("#### Operational Telemetry Log")
#             fig = go.Figure(data=[go.Bar(
#                 x=['Credentials Checked', 'URLs Analyzed', 'Phishing Emails'],
#                 y=[st.session_state.pwd_scans, st.session_state.url_scans, st.session_state.email_scans],
#                 marker_color=['#3B82F6', '#F59E0B', '#EF4444'],
#                 width=0.4
#             )])
#             fig.update_layout(
#                 paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
#                 font_color='#94A3B8', height=250, margin=dict(l=10, r=10, t=10, b=10),
#                 yaxis=dict(gridcolor='#334155', zeroline=False)
#             )
#             st.plotly_chart(fig, use_container_width=True)
#     with col_g2:
#         with st.container(border=True):
#             st.markdown("#### Real-time Scanner Feed")
#             if st.session_state.total_scans == 0:
#                 st.info("📡 Scanner feed idling. Perform a security check to generate data log streams.")
#             else:
#                 st.success(f"✔️ Active Protection Active. Logged {st.session_state.total_scans} event interactions this session.")

# # 2. REMADE PASSWORD ANALYZER
# elif menu_choice == "Password Analyzer":
#     st.markdown("<div class='cyber-title'>🔐 Password Strength Analyzer</div>", unsafe_allow_html=True)
#     st.markdown("<div class='cyber-subtitle'>Evaluate credential resilience using Shannon entropy mappings and safety check criteria.</div>", unsafe_allow_html=True)
    
#     with st.container(border=True):
#         password_input = st.text_input("Enter a password string to analyze:", type="password", placeholder="Type password profile here...")

#     if password_input:
#         if 'last_pwd' not in st.session_state or st.session_state.last_pwd != password_input:
#             st.session_state.total_scans += 1
#             st.session_state.pwd_scans += 1
#             st.session_state.last_pwd = password_input
            
#         res = check_password_strength(password_input)
        
#         if res['category'] in ["Weak", "Medium"] and f"pwd_flag_{password_input}" not in st.session_state:
#             st.session_state.threats_blocked += 1
#             st.session_state[f"pwd_flag_{password_input}"] = True

#         st.markdown("### 📊 Assessment Report")
#         col1, col2 = st.columns([1, 1.2], gap="large")
        
#         with col1:
#             with st.container(border=True):
#                 st.markdown("#### Analysis Metrics")
#                 if res['category'] == "Strong":
#                     st.success(f"🟢 Category: {res['category'].upper()}")
#                 elif res['category'] == "Medium":
#                     st.warning(f"🟡 Category: {res['category'].upper()}")
#                 else:
#                     st.error(f"🔴 Category: {res['category'].upper()}")
                
#                 st.markdown("<br>", unsafe_allow_html=True)
#                 st.progress(res['score'] / 5.0, text=f"Security Score: {res['score']}/5")
#                 st.metric(label="Calculated Password Entropy", value=f"{res['entropy']} bits")
                
#                 if res['entropy'] < 40:
#                     st.caption("⚠️ **Entropy < 40 bits:** Weak structural density. Vulnerable to fast dictionary attacks.")
#                 elif res['entropy'] < 60:
#                     st.caption("⚠️ **Entropy < 60 bits:** Moderate security. Vulnerable to optimized cluster cracking.")
#                 else:
#                     st.caption("✅ **Entropy 60+ bits:** Safe distribution density against standard brute-force vectors.")

#         with col2:
#             with st.container(border=True):
#                 st.markdown("#### Complexity Breakdown")
#                 st.checkbox("Meets standard baseline length (≥ 8 chars)", value=(res['length'] >= 8), disabled=True)
#                 st.checkbox("Contains uppercase letters (A-Z)", value=res['has_upper'], disabled=True)
#                 st.checkbox("Contains lowercase letters (a-z)", value=res['has_lower'], disabled=True)
#                 st.checkbox("Contains numeric characters (0-9)", value=res['has_digits'], disabled=True)
#                 st.checkbox("Contains special character indicators (!, @, #, $...)", value=res['has_special'], disabled=True)
            
#             st.markdown("<br>", unsafe_allow_html=True)
#             with st.container(border=True):
#                 st.markdown("#### Improvement Recommendations")
#                 for tip in res['feedback']:
#                     st.markdown(tip)

# # 3. REMADE URL ANALYZER
# elif menu_choice == "URL Analyzer":
#     st.markdown("<div class='cyber-title'>🌐 URL Risk Analyzer</div>", unsafe_allow_html=True)
#     st.markdown("<div class='cyber-subtitle'>Scan domain pointers and address syntax for common fraud patterns.</div>", unsafe_allow_html=True)
    
#     with st.container(border=True):
#         url_input = st.text_input("Enter target URL address payload:", placeholder="example-secure-login.com/verify")

#     if url_input:
#         if 'last_url' not in st.session_state or st.session_state.last_url != url_input:
#             st.session_state.total_scans += 1
#             st.session_state.url_scans += 1
#             st.session_state.last_url = url_input

#         res = analyze_url_risk(url_input)
        
#         if res['classification'] in ["Suspicious", "Dangerous"] and f"url_flag_{url_input}" not in st.session_state:
#             st.session_state.threats_blocked += 1
#             st.session_state[f"url_flag_{url_input}"] = True

#         st.markdown("### 📊 Scan Summary")
#         col1, col2 = st.columns([1, 1.2], gap="large")
        
#         with col1:
#             with st.container(border=True):
#                 st.markdown("#### Threat Metrics")
#                 if res['classification'] == "Safe":
#                     st.success(f"🟢 Verdict: {res['classification'].upper()}")
#                 elif res['classification'] == "Suspicious":
#                     st.warning(f"🟡 Verdict: {res['classification'].upper()}")
#                 else:
#                     st.error(f"🔴 Verdict: {res['classification'].upper()}")
                
#                 st.markdown("<br>", unsafe_allow_html=True)
#                 st.progress(res['risk_score'] / 100.0, text=f"Calculated Risk Score: {res['risk_score']}%")
                
#                 st.markdown("---")
#                 st.markdown("**Structural Metadata:**")
#                 st.markdown(f"• URL Character Count: `{res['length']}`")
#                 st.markdown(f"• Domain Dot Separation: `{res['dots']}`")
#                 st.markdown(f"• Contains Direct IP Route: `{res['has_ip']}`")

#         with col2:
#             with st.container(border=True):
#                 st.markdown("#### Identified Risks & Reasons")
#                 for reason in res['reasons']:
#                     st.markdown(reason)

# # 4. EMAIL DETECTOR 
# elif menu_choice == "Email Detector":
#     st.markdown("<div class='cyber-title'>📧 Phishing Email Detector</div>", unsafe_allow_html=True)
#     st.markdown("<div class='cyber-subtitle'>Analyze message copy against trained machine learning vector matrices.</div>", unsafe_allow_html=True)
    
#     with st.container(border=True):
#         email_input = st.text_area("Paste email message content payload:", placeholder="Paste text here...", height=140)

#     if email_input:
#         if 'last_email' not in st.session_state or st.session_state.last_email != email_input:
#             st.session_state.total_scans += 1
#             st.session_state.email_scans += 1
#             st.session_state.last_email = email_input

#         res = analyze_email_content(email_input)
#         if res['verdict'] == "Phishing" and f"email_flag_{hash(email_input)}" not in st.session_state:
#             st.session_state.threats_blocked += 1
#             st.session_state[f"email_flag_{hash(email_input)}"] = True

#         col1, col2 = st.columns(2, gap="large")
#         with col1:
#             with st.container(border=True):
#                 if res['verdict'] == "Phishing":
#                     st.markdown(f"#### Engine Result: <span style='color:#EF4444;'>🚨 {res['verdict'].upper()} SPOTTED</span>", unsafe_allow_html=True)
#                 else:
#                     st.markdown(f"#### Engine Result: <span style='color:#10B981;'>🟢 {res['verdict'].upper()} MATCH</span>", unsafe_allow_html=True)
                
#                 st.progress(res['confidence'] / 100.0, text=f"Classifier Confidence: {res['confidence']}%")
#         with col2:
#             with st.container(border=True):
#                 st.markdown("#### Suspicious Language Indicators")
#                 for trigger in res['triggers']:
#                     st.markdown(trigger)


import streamlit as st
import plotly.graph_objects as go
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
    </style>
""", unsafe_allow_html=True)

# --- SESSION STATES ---
if 'total_scans' not in st.session_state: st.session_state.total_scans = 0
if 'threats_blocked' not in st.session_state: st.session_state.threats_blocked = 0
if 'pwd_scans' not in st.session_state: st.session_state.pwd_scans = 0
if 'url_scans' not in st.session_state: st.session_state.url_scans = 0
if 'email_scans' not in st.session_state: st.session_state.email_scans = 0

# --- SIDEBAR NAV ---
with st.sidebar:
    st.title("🛡️ CyberShield AI")
    st.caption("Intelligent Digital Safety Platform")
    st.markdown("---")
    menu_choice = st.radio("Navigation Menu", ["Dashboard", "Password Analyzer", "URL Analyzer", "Email Detector"])

# --- CORE SUBSYSTEM ROUTING ---

# 1. DASHBOARD
if menu_choice == "Dashboard":
    st.title("📊 Security Command Center")
    st.markdown("<div class='cyber-subtitle'>Real-time session security indicators and processed threat logs.</div>", unsafe_allow_html=True)
    
    col_m1, col_m2, col_m3 = st.columns(3)
    with col_m1:
        st.metric(label="Total Ecosystem Scans", value=st.session_state.total_scans)
    with col_m2:
        safety_score = max(100 - (st.session_state.threats_blocked * 15), 45)
        st.metric(label="System Security Index", value=f"{safety_score}%")
    with col_m3:
        st.metric(label="Identified Threats Flagged", value=st.session_state.threats_blocked)

    st.markdown("<br>", unsafe_allow_html=True)
    col_g1, col_g2 = st.columns([1.5, 1], gap="medium")
    
    with col_g1:
        with st.container(border=True):
            st.markdown("#### Operational Telemetry Log")
            fig = go.Figure(data=[go.Bar(
                x=['Credentials Checked', 'URLs Analyzed', 'Phishing Emails'],
                y=[st.session_state.pwd_scans, st.session_state.url_scans, st.session_state.email_scans],
                marker_color=['#3B82F6', '#F59E0B', '#EF4444'],
                width=0.4
            )])
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font_color='#94A3B8', height=250, margin=dict(l=10, r=10, t=10, b=10),
                yaxis=dict(gridcolor='#334155', zeroline=False)
            )
            st.plotly_chart(fig, use_container_width=True)
    with col_g2:
        with st.container(border=True):
            st.markdown("#### Real-time Scanner Feed")
            if st.session_state.total_scans == 0:
                st.info("📡 Scanner feed idling. Perform a security check to generate data log streams.")
            else:
                st.success(f"✔️ Active Protection Active. Logged {st.session_state.total_scans} event interactions this session.")

# 2. PASSWORD ANALYZER
elif menu_choice == "Password Analyzer":
    st.title("🔐 Password Strength Analyzer")
    st.markdown("<div class='cyber-subtitle'>Evaluate credential resilience using Shannon entropy mappings and safety check criteria.</div>", unsafe_allow_html=True)
    
    with st.container(border=True):
        password_input = st.text_input("Enter a password string to analyze:", type="password", placeholder="Type password profile here...")

    if password_input:
        if 'last_pwd' not in st.session_state or st.session_state.last_pwd != password_input:
            st.session_state.total_scans += 1
            st.session_state.pwd_scans += 1
            st.session_state.last_pwd = password_input
            
        res = check_password_strength(password_input)
        
        if res['category'] in ["Weak", "Medium"] and f"pwd_flag_{password_input}" not in st.session_state:
            st.session_state.threats_blocked += 1
            st.session_state[f"pwd_flag_{password_input}"] = True

        st.markdown("### 📊 Assessment Report")
        col1, col2 = st.columns([1, 1.2], gap="large")
        
        with col1:
            with st.container(border=True):
                st.markdown("#### Analysis Metrics")
                if res['category'] == "Strong":
                    st.success(f"🟢 Category: {res['category'].upper()}")
                elif res['category'] == "Medium":
                    st.warning(f"🟡 Category: {res['category'].upper()}")
                else:
                    st.error(f"🔴 Category: {res['category'].upper()}")
                
                st.markdown("<br>", unsafe_allow_html=True)
                st.progress(res['score'] / 5.0, text=f"Security Score: {res['score']}/5")
                st.metric(label="Calculated Password Entropy", value=f"{res['entropy']} bits")

        with col2:
            with st.container(border=True):
                st.markdown("#### Complexity Breakdown")
                st.checkbox("Meets standard baseline length (≥ 8 chars)", value=(res['length'] >= 8), disabled=True)
                st.checkbox("Contains uppercase letters (A-Z)", value=res['has_upper'], disabled=True)
                st.checkbox("Contains lowercase letters (a-z)", value=res['has_lower'], disabled=True)
                st.checkbox("Contains numeric characters (0-9)", value=res['has_digits'], disabled=True)
                st.checkbox("Contains special character indicators (!, @, #, $...)", value=res['has_special'], disabled=True)
            
            st.markdown("<br>", unsafe_allow_html=True)
            with st.container(border=True):
                st.markdown("#### Improvement Recommendations")
                for tip in res['feedback']:
                    st.markdown(tip)

# 3. URL ANALYZER
elif menu_choice == "URL Analyzer":
    st.title("🌐 URL Risk Analyzer")
    st.markdown("<div class='cyber-subtitle'>Scan domain pointers and address syntax for common fraud patterns.</div>", unsafe_allow_html=True)
    
    with st.container(border=True):
        url_input = st.text_input("Enter target URL address payload:", placeholder="example-secure-login.com/verify")

    if url_input:
        if 'last_url' not in st.session_state or st.session_state.last_url != url_input:
            st.session_state.total_scans += 1
            st.session_state.url_scans += 1
            st.session_state.last_url = url_input

        res = analyze_url_risk(url_input)
        
        if res['classification'] in ["Suspicious", "Dangerous"] and f"url_flag_{url_input}" not in st.session_state:
            st.session_state.threats_blocked += 1
            st.session_state[f"url_flag_{url_input}"] = True

        st.markdown("### 📊 Scan Summary")
        col1, col2 = st.columns([1, 1.2], gap="large")
        
        with col1:
            with st.container(border=True):
                st.markdown("#### Threat Metrics")
                if res['classification'] == "Safe":
                    st.success(f"🟢 Verdict: {res['classification'].upper()}")
                elif res['classification'] == "Suspicious":
                    st.warning(f"🟡 Verdict: {res['classification'].upper()}")
                else:
                    st.error(f"🔴 Verdict: {res['classification'].upper()}")
                
                st.markdown("<br>", unsafe_allow_html=True)
                st.progress(res['risk_score'] / 100.0, text=f"Calculated Risk Score: {res['risk_score']}%")
                
                st.markdown("---")
                st.markdown("**Structural Metadata:**")
                st.markdown(f"• URL Character Count: `{res['length']}`")
                st.markdown(f"• Domain Dot Separation: `{res['dots']}`")
                st.markdown(f"• Contains Direct IP Route: `{res['has_ip']}`")

        with col2:
            with st.container(border=True):
                st.markdown("#### Identified Risks & Reasons")
                for reason in res['reasons']:
                    st.markdown(reason)

# 4. EMAIL DETECTOR 
elif menu_choice == "Email Detector":
    st.title("📧 Phishing Email Detector")
    st.markdown("<div class='cyber-subtitle'>Analyze message copy against trained machine learning vector matrices.</div>", unsafe_allow_html=True)
    
    with st.container(border=True):
        email_input = st.text_area("Paste email message content payload:", placeholder="Paste text here...", height=140)

    if email_input:
        if 'last_email' not in st.session_state or st.session_state.last_email != email_input:
            st.session_state.total_scans += 1
            st.session_state.email_scans += 1
            st.session_state.last_email = email_input

        res = analyze_email_content(email_input)
        if res['verdict'] == "Phishing" and f"email_flag_{hash(email_input)}" not in st.session_state:
            st.session_state.threats_blocked += 1
            st.session_state[f"email_flag_{hash(email_input)}"] = True

        st.markdown("### 📊 Evaluation Report")
        col1, col2 = st.columns([1, 1.2], gap="large")
        with col1:
            with st.container(border=True):
                st.markdown("#### Classification Metrics")
                if res['verdict'] == "Phishing":
                    st.error(f"🚨 Verdict: {res['verdict'].upper()} DETECTED")
                else:
                    st.success(f"🟢 Verdict: CLEAN ({res['verdict'].upper()})")
                
                st.markdown("<br>", unsafe_allow_html=True)
                st.progress(res['confidence'] / 100.0, text=f"ML Classifier Confidence: {res['confidence']}%")
        with col2:
            with st.container(border=True):
                st.markdown("#### High-Risk Text Patterns Caught")
                for trigger in res['triggers']:
                    st.markdown(trigger)