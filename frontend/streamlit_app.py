"""
Alternative Streamlit Interface for PhishGuard AI.
Connects to the FastAPI backend API and displays results with a custom dark-red cyber theme.
"""

import streamlit as st
import requests
import json
import pandas as pd

# API endpoint URL
API_URL = "http://127.0.0.1:8000/api/v1"

# Page config
st.set_page_config(
    page_title="PhishGuard AI - Email Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyberpunk CSS styling
st.markdown("""
<style>
    /* Dark cyber theme injection */
    .stApp {
        background-color: #0b0b0f;
        color: #f5f5f7;
    }
    
    /* Headers styling */
    h1, h2, h3 {
        font-family: 'Outfit', sans-serif;
        color: #ffffff !important;
    }
    
    .cyber-title {
        font-size: 2.5rem;
        font-weight: 800;
        letter-spacing: 1px;
        margin-bottom: 0.2rem;
    }
    
    .cyber-title span {
        color: #ff003c;
    }
    
    .cyber-sub {
        font-size: 0.9rem;
        color: #9fa2b4;
        margin-bottom: 2rem;
    }
    
    /* Card design */
    .cyber-card {
        background-color: #12121a;
        border: 1px solid rgba(255, 0, 60, 0.2);
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 20px;
        box-shadow: 0 0 15px rgba(255, 0, 60, 0.03);
    }
    
    .metric-val {
        font-size: 1.8rem;
        font-weight: 700;
        font-family: 'Outfit', sans-serif;
    }
    
    /* Threat level colors */
    .text-red { color: #ff003c; }
    .text-yellow { color: #ffd600; }
    .text-green { color: #00e676; }
    
    /* Table modifications */
    .dataframe {
        background-color: #12121a !important;
        color: #f5f5f7 !important;
        border: 1px solid rgba(255, 0, 60, 0.15) !important;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown('<div class="cyber-title">PHISHGUARD<span>AI</span></div>', unsafe_allow_html=True)
    st.markdown('<p class="cyber-sub">AI-Powered Email Security</p>', unsafe_allow_html=True)
    
    st.write("---")
    st.write("### Connection Diagnostic")
    
    # Check if backend is running
    backend_active = False
    try:
        res = requests.get(f"{API_URL}/history")
        if res.status_code == 200:
            backend_active = True
    except Exception:
        pass
        
    if backend_active:
        st.success("API Server: ACTIVE")
    else:
        st.error("API Server: OFFLINE")
        st.warning("Please run FastAPI: 'python backend/main.py'")

# Main Content Layout
st.markdown('<div class="cyber-title">AI Phishing <span>Email Detector</span></div>', unsafe_allow_html=True)
st.markdown('<p class="cyber-sub">Detect. Analyze. Protect. (Streamlit Portal)</p>', unsafe_allow_html=True)

tab1, tab2 = st.tabs(["📧 Email Scanning Workspace", "📊 Historical logs & Metrics"])

with tab1:
    col_input, col_shield = st.columns([2, 1])
    
    with col_input:
        st.write("### Choose Input Method")
        input_type = st.radio("Select input source:", ["Upload File (.eml, .txt, .msg)", "Paste Email Text"], label_visibility="collapsed")
        
        scan_data = None
        
        if input_type == "Paste Email Text":
            pasted_text = st.text_area("Suspicious Email Content:", height=250, placeholder="Paste the subject, headers, and body here...")
            if st.button("Scan Text", use_container_width=True):
                if not pasted_text.strip():
                    st.warning("Please paste email text content first.")
                else:
                    scan_data = {"text": pasted_text}
                    
        else:
            uploaded_file = st.file_uploader("Drag and drop your file here:", type=["txt", "eml", "msg"])
            if uploaded_file is not None:
                file_bytes = uploaded_file.read()
                scan_data = {"file": (uploaded_file.name, file_bytes, uploaded_file.type)}
                
    with col_shield:
        st.markdown("""
        <div class="cyber-card" style="text-align: center;">
            <h3 style="margin-bottom: 12px;">Security Status</h3>
            <div style="font-size: 80px; color: #ff003c; margin: 20px 0; text-shadow: 0 0 20px rgba(255,0,60,0.3);">
                🛡️
            </div>
            <p style="font-size: 13px; color: #9fa2b4;">Ready to scan email threats. Upload or paste headers and body to test.</p>
        </div>
        """, unsafe_allow_html=True)

    # Perform analysis
    if scan_data:
        st.write("---")
        st.write("## 🔍 Threat Analysis Results")
        
        with st.spinner("AI engine performing multi-layered threat evaluation..."):
            try:
                if "text" in scan_data:
                    res = requests.post(f"{API_URL}/scan", data={"text": scan_data["text"]})
                else:
                    files = {"file": scan_data["file"]}
                    res = requests.post(f"{API_URL}/scan", files=files)
                    
                if res.status_code == 200:
                    report = res.json()
                    
                    # Display metrics
                    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
                    
                    pred = report["analysis"]["prediction"]
                    conf = report["analysis"]["confidence"]
                    risk = report["analysis"]["risk_score"]
                    level = report["analysis"]["threat_level"]
                    color_tag = "text-red" if level in ["HIGH", "CRITICAL"] else "text-yellow" if level == "MEDIUM" else "text-green"
                    
                    m_col1.markdown(f'<div class="cyber-card"><h4>Prediction</h4><span class="metric-val {color_tag}">{pred}</span></div>', unsafe_allow_html=True)
                    m_col2.markdown(f'<div class="cyber-card"><h4>Confidence</h4><span class="metric-val">{conf*100:.2f}%</span></div>', unsafe_allow_html=True)
                    m_col3.markdown(f'<div class="cyber-card"><h4>Threat Score</h4><span class="metric-val {color_tag}">{risk}/100</span></div>', unsafe_allow_html=True)
                    m_col4.markdown(f'<div class="cyber-card"><h4>Risk Level</h4><span class="metric-val {color_tag}">{level}</span></div>', unsafe_allow_html=True)
                    
                    # Detailed results columns
                    res_col1, res_col2 = st.columns(2)
                    
                    with res_col1:
                        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
                        st.write("### Email Metadata Breakdown")
                        st.write(f"**From:** {report['email_details']['from']}")
                        st.write(f"**To:** {report['email_details']['to']}")
                        st.write(f"**Subject:** {report['email_details']['subject']}")
                        st.write(f"**Total Links:** {report['email_details']['links_count']}")
                        st.write(f"**File Attachments:** {report['email_details']['attachments_count']}")
                        st.write(f"**Model Engine:** {report['analysis']['model_used']}")
                        st.markdown('</div>', unsafe_allow_html=True)
                        
                        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
                        st.write("### Recommended Defensive Actions")
                        for rec in report["recommendations"]:
                            st.write(f"⚠️ {rec}")
                        st.markdown('</div>', unsafe_allow_html=True)
                        
                    with res_col2:
                        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
                        st.write("### Triggered Threat Heuristics")
                        if report["explainability"]["indicators"]:
                            for ind in report["explainability"]["indicators"]:
                                st.write(f"🚨 {ind}")
                        else:
                            st.write("✅ No critical static heuristics triggered.")
                        st.markdown('</div>', unsafe_allow_html=True)
                        
                        # Probabilities Chart
                        st.write("### Prediction Category Probability")
                        probs = report["analysis"]["probabilities"]
                        chart_df = pd.DataFrame({
                            "Category": ["Phishing", "Spam", "Legitimate"],
                            "Probability (%)": [probs["phishing"]*100, probs["spam"]*100, probs["legitimate"]*100]
                        })
                        st.bar_chart(chart_df.set_index("Category"))
                        
                else:
                    st.error(f"Scan API returned error: {res.text}")
            except Exception as e:
                st.error(f"Unable to connect to scan service: {str(e)}")

with tab2:
    st.write("### Historic Prediction Audit logs")
    if backend_active:
        try:
            history_res = requests.get(f"{API_URL}/history")
            if history_res.status_code == 200:
                history_data = history_res.json()
                if history_data:
                    df = pd.DataFrame(history_data)
                    df_display = df[["id", "created_at", "sender", "subject", "threat_category", "risk_score"]]
                    st.dataframe(df_display, use_container_width=True)
                else:
                    st.info("No records in history database yet.")
        except Exception as e:
            st.error(f"Error fetching history logs: {e}")
            
        st.write("---")
        st.write("### System Statistics")
        try:
            stats_res = requests.get(f"{API_URL}/stats")
            if stats_res.status_code == 200:
                stats = stats_res.json()
                sc1, sc2, sc3 = st.columns(3)
                sc1.metric("Total Scanned Emails", stats["total_scans"])
                sc2.metric("Average Threat Score", f"{stats['avg_confidence']}%")
                sc3.metric("Average Inference Speed", f"{stats['avg_speed_ms']} ms")
        except Exception:
            st.info("System statistics unavailable.")
    else:
        st.info("Diagnostic database offline. Please launch the backend main server.")
