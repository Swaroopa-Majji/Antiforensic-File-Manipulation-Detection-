import streamlit as st
import pandas as pd
from execution_bridge import analyze_advanced_anti_forensics, generate_pdf_report

st.set_page_config(page_title="Anti-Forensic Workstation", layout="wide")

# Standard markdown styling definitions targeting high-contrast executive theme limits
st.markdown("""
    <style>
    .main { background-color: #0F172A; color: #F8FAFC; }
    .stApp { background-color: #0F172A; color: #F8FAFC; }
    .logo-container { text-align: center; margin-bottom: -10px; padding-top: 10px; }
    .logo-icon { font-size: 55px; color: #38BDF8; }
    h1 { color: #38BDF8; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-weight: 800; text-align: center; margin-top: 5px; }
    .sub-bar { text-align: center; color: #94A3B8; font-weight: 600; margin-bottom: 25px; }
    label { color: #94A3B8 !important; font-weight: 600; }
    .metric-card { background-color: #1E293B; border: 1px solid #334155; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2); }
    .metric-val { color: #38BDF8; font-size: 26px; font-weight: 700; }
    .metric-lbl { color: #94A3B8; font-size: 13px; text-transform: uppercase; margin-bottom: 5px; }
    div.stDownloadButton > button { background-color: #0284C7 !important; color: #FFFFFF !important; border-radius: 6px !important; border: none !important; font-weight: bold !important; height: 45px; box-shadow: 0 4px 6px -1px rgba(2, 132, 199, 0.3); }
    div.stDownloadButton > button:hover { background-color: #0369A1 !important; }
    </style>
""", unsafe_allow_html=True)

# Main Formatted Station Structural Headers
st.markdown("<div class='logo-container'><span class='logo-icon'>🛡️</span></div>", unsafe_allow_html=True)
st.markdown("# FORENSIC REPORT FOR ANTI-FORENSIC FILE MANIPULATION DETECTION")
st.markdown("<div class='sub-bar'>Advanced Adaptive Rule-Based Framework | Operational Real-Time Investigation Terminal</div>", unsafe_allow_html=True)
st.markdown("---")

uploaded_file = st.file_uploader("📂 Drag and Drop Target Evidence File Asset for Live Verification", type=None)

if uploaded_file is not None:
    filename = uploaded_file.name
    
    with st.spinner("Executing structural chunk feature analytics in real time..."):
        file_bytes = uploaded_file.read()
        report_data = analyze_advanced_anti_forensics(file_bytes, filename)
        
    # Standard grid layout matrix row
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"<div class='metric-card'><div class='metric-lbl'>Danger Index Score</div><div class='metric-val'>{report_data['rule_score']} / 100</div></div>", unsafe_allow_html=True)
    with m2:
        st.markdown(f"<div class='metric-card'><div class='metric-lbl'>Framework Threat Level</div><div class='metric-val' style='color:#EF4444;'>{report_data['threat_level']}</div></div>", unsafe_allow_html=True)
    with m3:
        st.markdown(f"<div class='metric-card'><div class='metric-lbl'>Global Shannon Entropy</div><div class='metric-val' style='color:#10B981;'>{report_data['global_entropy']}</div></div>", unsafe_allow_html=True)
    with m4:
        st.markdown(f"<div class='metric-card'><div class='metric-lbl'>Analyzed Data Mass</div><div class='metric-val'>{report_data['size_mb']} MB</div></div>", unsafe_allow_html=True)
        
    st.markdown("<br/>", unsafe_allow_html=True)
    col_l, col_r = st.columns(2)
    
    with col_l:
        st.markdown("### 📊 Intercepted Anti-Forensic Anomalies")
        if report_data["techniques"]:
            for tech, desc in report_data["techniques"].items():
                st.error(f"🚨 **{tech}**: {desc}")
        else:
            st.success("✅ **Baseline Clear:** No active structural anomalies or anti-forensic techniques identified.")
            
        st.markdown("#### Cryptographic Fingerprints Data Integrity")
        st.code(f"MD5    : {report_data['md5']}\nSHA-1  : {report_data['sha1']}\nSHA-256: {report_data['sha256']}", language="text")

    with col_r:
        st.markdown("### 📑 Report Generation Engine")
        st.write("Compile formal multi-tier structured assessment metrics matching verification style guidelines for legal chain of custody documentation.")
        
        pdf_filename = generate_pdf_report(report_data)
        with open(pdf_filename, "rb") as pdf_file:
            st.download_button(
                label="📥 Download Formal Multi-Table Forensic Report",
                data=pdf_file,
                file_name=f"Forensic_Report_{filename}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
            
        st.markdown("<br/>", unsafe_allow_html=True)
        st.markdown("#### 🔬 Framework Real-Time Log Diagnostics")
        st.write(f"- **Extracted Magic Bytes Header:** `{report_data['magic_bytes']}`")
        st.write(f"- **Identified Structural Context:** `{report_data['detected_sig']}`")
        st.write(f"- **Extension Consistency Match:** `Mismatch Status: {report_data['ext_mismatch']}`")
