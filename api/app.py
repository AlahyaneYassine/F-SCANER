# ============================================================
# app.py — Interface Streamlit Cybersécurité
# Design : Terminal/Matrix noir + accents néon cyan/rouge
# ============================================================
import streamlit as st
import requests
import hashlib
import time
import plotly.graph_objects as go
from datetime import datetime

st.set_page_config(
    page_title="F-SCANER — Malware Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CSS Cybersécurité professionnel ────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Orbitron:wght@400;700;900&display=swap');

:root {
    --bg-void:      #020408;
    --bg-deep:      #050d14;
    --bg-card:      #071520;
    --bg-elevated:  #0a1f30;
    --cyan:         #00d4ff;
    --cyan-dim:     #00a8cc;
    --cyan-glow:    rgba(0,212,255,0.15);
    --cyan-border:  rgba(0,212,255,0.25);
    --red:          #ff2d55;
    --red-glow:     rgba(255,45,85,0.15);
    --red-border:   rgba(255,45,85,0.3);
    --green:        #00ff88;
    --green-glow:   rgba(0,255,136,0.1);
    --green-border: rgba(0,255,136,0.25);
    --orange:       #ff9500;
    --text-primary: #e2eeff;
    --text-dim:     #6b8aaa;
    --text-mono:    #4a9ebb;
    --font-ui:      'Rajdhani', sans-serif;
    --font-mono:    'Share Tech Mono', monospace;
    --font-display: 'Orbitron', monospace;
}

/* ── Reset global ── */
html, body, .stApp {
    background: var(--bg-void) !important;
    color: var(--text-primary) !important;
    font-family: var(--font-ui) !important;
}

/* ── Grid background ── */
.stApp::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
        linear-gradient(rgba(0,212,255,0.03) 1px,
                        transparent 1px),
        linear-gradient(90deg,
                        rgba(0,212,255,0.03) 1px,
                        transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
}

/* ── Scan line animation ── */
.stApp::after {
    content: '';
    position: fixed;
    top: -100%;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(90deg,
        transparent,
        var(--cyan),
        transparent);
    animation: scanline 8s linear infinite;
    pointer-events: none;
    z-index: 1;
    opacity: 0.4;
}
@keyframes scanline {
    0%   { top: -2px; }
    100% { top: 100vh; }
}

/* ── Header principal ── */
.cyber-header {
    position: relative;
    background: linear-gradient(135deg,
        #020d1a 0%, #041525 50%, #020d1a 100%);
    border: 1px solid var(--cyan-border);
    border-radius: 4px;
    padding: 28px 36px;
    margin-bottom: 24px;
    overflow: hidden;
    box-shadow:
        0 0 40px rgba(0,212,255,0.08),
        inset 0 1px 0 rgba(0,212,255,0.1);
}
.cyber-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg,
        transparent, var(--cyan), transparent);
    animation: headerPulse 3s ease-in-out infinite;
}
@keyframes headerPulse {
    0%,100% { opacity: 0.4; }
    50%      { opacity: 1; }
}
.cyber-header-title {
    font-family: var(--font-display) !important;
    font-size: 1.6em;
    font-weight: 900;
    color: var(--cyan) !important;
    letter-spacing: 0.1em;
    text-shadow: 0 0 20px rgba(0,212,255,0.5);
    margin: 0;
}
.cyber-header-sub {
    font-family: var(--font-mono);
    font-size: 0.78em;
    color: var(--text-dim);
    margin-top: 8px;
    letter-spacing: 0.05em;
}
.cyber-header-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(0,212,255,0.08);
    border: 1px solid var(--cyan-border);
    padding: 4px 12px;
    border-radius: 2px;
    font-family: var(--font-mono);
    font-size: 0.7em;
    color: var(--cyan-dim);
    margin-top: 12px;
}

/* ── Cards ── */
.cyber-card {
    background: var(--bg-card);
    border: 1px solid rgba(0,212,255,0.1);
    border-radius: 4px;
    padding: 20px;
    margin-bottom: 16px;
    position: relative;
    overflow: hidden;
}
.cyber-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 3px; height: 100%;
    background: var(--cyan);
    opacity: 0.6;
}

/* ── Section titles ── */
.section-title {
    font-family: var(--font-display);
    font-size: 0.75em;
    letter-spacing: 0.15em;
    color: var(--cyan);
    text-transform: uppercase;
    border-bottom: 1px solid var(--cyan-border);
    padding-bottom: 8px;
    margin-bottom: 16px;
}

/* ── Verdict BÉNIN ── */
.verdict-benin {
    background: linear-gradient(135deg,
        #011a0d 0%, #02230f 100%);
    border: 1px solid var(--green-border);
    border-radius: 4px;
    padding: 28px;
    text-align: center;
    position: relative;
    overflow: hidden;
    box-shadow: 0 0 40px var(--green-glow),
                inset 0 0 40px rgba(0,255,136,0.02);
}
.verdict-benin::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg,
        transparent, var(--green), transparent);
}
.verdict-benin-text {
    font-family: var(--font-display);
    font-size: 1.8em;
    font-weight: 900;
    color: var(--green);
    letter-spacing: 0.15em;
    text-shadow: 0 0 30px rgba(0,255,136,0.6);
}

/* ── Verdict MALWARE ── */
.verdict-malware {
    background: linear-gradient(135deg,
        #1a0108 0%, #230209 100%);
    border: 1px solid var(--red-border);
    border-radius: 4px;
    padding: 28px;
    text-align: center;
    position: relative;
    overflow: hidden;
    box-shadow: 0 0 40px var(--red-glow),
                inset 0 0 40px rgba(255,45,85,0.02);
    animation: threatPulse 2s ease-in-out infinite;
}
@keyframes threatPulse {
    0%,100% {
        box-shadow: 0 0 40px var(--red-glow); }
    50% {
        box-shadow: 0 0 60px rgba(255,45,85,0.25); }
}
.verdict-malware::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg,
        transparent, var(--red), transparent);
    animation: redScan 2s ease-in-out infinite;
}
@keyframes redScan {
    0%,100% { opacity: 0.6; }
    50%      { opacity: 1; }
}
.verdict-malware-text {
    font-family: var(--font-display);
    font-size: 1.8em;
    font-weight: 900;
    color: var(--red);
    letter-spacing: 0.15em;
    text-shadow: 0 0 30px rgba(255,45,85,0.7);
}

/* ── Confidence bar ── */
.conf-container {
    background: rgba(0,0,0,0.4);
    border: 1px solid rgba(0,212,255,0.1);
    border-radius: 4px;
    padding: 16px 20px;
    margin: 12px 0;
}
.conf-label {
    font-family: var(--font-mono);
    font-size: 0.7em;
    color: var(--text-dim);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 10px;
}
.conf-track {
    background: rgba(255,255,255,0.04);
    height: 6px;
    border-radius: 3px;
    overflow: hidden;
}
.conf-fill-green {
    height: 100%;
    border-radius: 3px;
    background: linear-gradient(90deg,
        #00cc6a, #00ff88);
    box-shadow: 0 0 8px rgba(0,255,136,0.5);
    transition: width 1s ease;
}
.conf-fill-red {
    height: 100%;
    border-radius: 3px;
    background: linear-gradient(90deg,
        #cc0022, #ff2d55);
    box-shadow: 0 0 8px rgba(255,45,85,0.5);
    transition: width 1s ease;
}
.conf-value {
    font-family: var(--font-display);
    font-size: 1.4em;
    font-weight: 700;
    text-align: center;
    margin-top: 8px;
}

/* ── File info card ── */
.file-info-card {
    background: var(--bg-elevated);
    border: 1px solid rgba(0,212,255,0.1);
    border-radius: 4px;
    padding: 14px 18px;
    font-family: var(--font-mono);
    font-size: 0.78em;
}
.file-info-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 5px 0;
    border-bottom: 1px solid rgba(0,212,255,0.05);
    color: var(--text-dim);
}
.file-info-row:last-child {
    border-bottom: none;
}
.file-info-key {
    color: var(--cyan-dim);
    letter-spacing: 0.05em;
}
.file-info-val {
    color: var(--text-primary);
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

/* ── Status badges ── */
.status-ok {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(0,255,136,0.08);
    border: 1px solid var(--green-border);
    color: var(--green);
    padding: 4px 10px;
    border-radius: 2px;
    font-family: var(--font-mono);
    font-size: 0.72em;
    letter-spacing: 0.05em;
}
.status-warn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(255,149,0,0.08);
    border: 1px solid rgba(255,149,0,0.3);
    color: var(--orange);
    padding: 4px 10px;
    border-radius: 2px;
    font-family: var(--font-mono);
    font-size: 0.72em;
    letter-spacing: 0.05em;
}
.status-err {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: var(--red-glow);
    border: 1px solid var(--red-border);
    color: var(--red);
    padding: 4px 10px;
    border-radius: 2px;
    font-family: var(--font-mono);
    font-size: 0.72em;
    letter-spacing: 0.05em;
}

/* ── Vote cards ── */
.vote-card {
    background: var(--bg-card);
    border-radius: 4px;
    padding: 14px 12px;
    text-align: center;
    border-top: 3px solid;
    position: relative;
    overflow: hidden;
    margin-bottom: 8px;
}
.vote-card.mal { border-color: var(--red); }
.vote-card.ben { border-color: var(--green); }
.vote-model {
    font-family: var(--font-mono);
    font-size: 0.65em;
    color: var(--text-dim);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 8px;
}
.vote-verdict {
    font-family: var(--font-display);
    font-size: 0.85em;
    font-weight: 700;
    letter-spacing: 0.05em;
}
.vote-verdict.mal { color: var(--red); }
.vote-verdict.ben { color: var(--green); }
.vote-proba {
    font-family: var(--font-mono);
    font-size: 0.7em;
    color: var(--text-dim);
    margin-top: 6px;
}

/* ── Metric boxes ── */
.metric-box {
    background: var(--bg-elevated);
    border: 1px solid rgba(0,212,255,0.1);
    border-radius: 4px;
    padding: 14px;
    text-align: center;
}
.metric-val {
    font-family: var(--font-display);
    font-size: 1.8em;
    font-weight: 700;
    color: var(--cyan);
}
.metric-lbl {
    font-family: var(--font-mono);
    font-size: 0.62em;
    color: var(--text-dim);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-top: 4px;
}

/* ── Progress steps ── */
.step-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 0;
    border-bottom: 1px solid rgba(0,212,255,0.05);
    font-family: var(--font-mono);
    font-size: 0.8em;
}
.step-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
}
.step-dot.done { background: var(--green);
    box-shadow: 0 0 6px var(--green); }
.step-dot.active { background: var(--cyan);
    box-shadow: 0 0 6px var(--cyan);
    animation: blink 1s infinite; }
.step-dot.wait { background: rgba(255,255,255,0.1); }
@keyframes blink {
    0%,100% { opacity: 1; }
    50%      { opacity: 0.3; }
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: var(--bg-deep) !important;
    border-right: 1px solid rgba(0,212,255,0.08) !important;
}
[data-testid="stSidebar"] * {
    font-family: var(--font-ui) !important;
    color: var(--text-primary) !important;
}

/* ── Buttons ── */
.stButton > button {
    background: transparent !important;
    border: 1px solid var(--cyan-border) !important;
    color: var(--cyan) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.85em !important;
    letter-spacing: 0.08em !important;
    border-radius: 2px !important;
    padding: 10px 20px !important;
    transition: all 0.2s !important;
    text-transform: uppercase !important;
}
.stButton > button:hover {
    background: var(--cyan-glow) !important;
    border-color: var(--cyan) !important;
    box-shadow: 0 0 15px var(--cyan-glow) !important;
}
.stDownloadButton > button {
    background: transparent !important;
    border: 1px solid rgba(139,92,246,0.4) !important;
    color: #a78bfa !important;
    font-family: var(--font-mono) !important;
    font-size: 0.85em !important;
    letter-spacing: 0.08em !important;
    border-radius: 2px !important;
    text-transform: uppercase !important;
}

/* ── File uploader ── */
[data-testid="stFileUploader"] {
    background: var(--bg-card) !important;
    border: 1px dashed var(--cyan-border) !important;
    border-radius: 4px !important;
    padding: 20px !important;
}
[data-testid="stFileUploader"] label {
    color: var(--cyan) !important;
    font-family: var(--font-mono) !important;
}

/* ── Progress ── */
.stProgress > div > div {
    background: linear-gradient(90deg,
        var(--cyan-dim), var(--cyan)) !important;
}

/* ── Hide branding ── */
#MainMenu, footer, header { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

API_URL = "http://localhost:8000"


def check_api():
    try:
        r = requests.get(f"{API_URL}/health",
                         timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def analyze_file(file_bytes, filename):
    files = {"file": (filename, file_bytes,
                       "application/octet-stream")}
    r = requests.post(f"{API_URL}/predict",
                      files=files, timeout=700)
    return r.json()


def get_report_pdf(file_bytes, filename):
    files = {"file": (filename, file_bytes,
                       "application/octet-stream")}
    r = requests.post(f"{API_URL}/report",
                      files=files, timeout=700)
    return r.content


# ── Session State ──────────────────────────────────────────
for k in ['result', 'file_bytes', 'filename',
           'analyzed']:
    if k not in st.session_state:
        st.session_state[k] = None

# ── Header ────────────────────────────────────────────────
api_ok = check_api()
now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

st.markdown(f"""
<div class="cyber-header">
  <div style="display:flex;
              justify-content:space-between;
              align-items:flex-start;">
    <div>
      <div class="cyber-header-title">
        ⬡ F-SCANER</div>
      <div class="cyber-header-sub">
        HYBRID MALWARE DETECTION SYSTEM
        — MACHINE LEARNING & DEEP LEARNING ENGINE </div>
      <div style="margin-top:12px;
                  display:flex; gap:10px;">
        <div class="cyber-header-badge">
          ◈ FIVE AI MODELS ACTIVE</div>
        <div class="cyber-header-badge">
          ◈ WEIGHTED VOTE ENGINE</div>
        <div class="cyber-header-badge">
          ◈ VIRUSTOTAL INTEGRATED</div>
      </div>
    </div>
    <div style="text-align:right;">
      <div style="font-family:var(--font-mono);
                  font-size:0.65em;
                  color:var(--text-dim);">
        SYSTEM TIME</div>
      <div style="font-family:var(--font-display);
                  font-size:0.75em;
                  color:var(--cyan);
                  margin-top:4px;">
        {now}</div>
      <div style="margin-top:8px;">
        {'<span class="status-ok">● API ONLINE</span>'
         if api_ok
         else '<span class="status-err">● API OFFLINE</span>'}
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Sidebar ────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="font-family:var(--font-display);
                font-size:0.8em;
                color:var(--cyan);
                letter-spacing:0.1em;
                border-bottom:1px solid
                rgba(0,212,255,0.2);
                padding-bottom:10px;
                margin-bottom:16px;">
      ◈ SYSTEM STATUS
    </div>
    """, unsafe_allow_html=True)

    if api_ok:
        st.success("API FastAPI — ONLINE")
    else:
        st.error("API FastAPI — OFFLINE")
        st.code(
            "python -m uvicorn main:app "
            "--port 8000", language="bash")

    st.markdown("""
    <div style="font-family:var(--font-display);
                font-size:0.8em;
                color:var(--cyan);
                letter-spacing:0.1em;
                border-bottom:1px solid
                rgba(0,212,255,0.2);
                padding-bottom:10px;
                margin-top:24px;
                margin-bottom:16px;">
      ◈ DETECTION PIPELINE
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="font-family:var(--font-mono);
                font-size:0.75em;
                color:var(--text-dim);
                line-height:1.8;">
      <div style="color:var(--cyan);
                  margin-bottom:8px;">
        STATIC ANALYSIS</div>
      → EMBER 2018 Feature Extractor<br>
      → 200 PE Structure Features<br>
      → lief Parser + Numpy Pipeline<br><br>
      <div style="color:var(--cyan);
                  margin-bottom:8px;">
        DYNAMIC ANALYSIS</div>
      → VirusTotal API v3<br>
      → 70+ AV Engine Consensus<br>
      → Behavioral Feature Mapping<br><br>
      <div style="color:var(--cyan);
                  margin-bottom:8px;">
        ML MODELS</div>
      → Random Forest<br>
      → XGBoost<br>
      → LightGBM<br>
      → CNN1D<br>
      → FT-Transformer<br><br>
      <div style="color:var(--cyan);
                  margin-bottom:8px;">
        FUSION STRATEGY</div>
      → Weighted Vote (val F1 scores)<br>
      → Threshold : 0.5
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="font-family:var(--font-display);
                font-size:0.8em;
                color:var(--cyan);
                letter-spacing:0.1em;
                border-bottom:1px solid
                rgba(0,212,255,0.2);
                padding-bottom:10px;
                margin-top:24px;
                margin-bottom:16px;">
      ◈ ACCEPTED FILES
    </div>
    <div style="font-family:var(--font-mono);
                font-size:0.72em;
                color:var(--text-dim);">
      FORMAT : .exe .dll .sys .ocx<br>
      MAX SIZE : 200 MB<br>
      ENGINE : PE32 / PE32+
    </div>
    """, unsafe_allow_html=True)

# ── Contenu principal ──────────────────────────────────────
col_left, col_right = st.columns([1, 1], gap="large")

with col_left:
    st.markdown("""
    <div class="section-title">
      ◈ FILE SUBMISSION</div>
    """, unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "DROP TARGET FILE",
        type=["exe", "dll", "sys", "ocx"],
        label_visibility="collapsed")

    if uploaded:
        fb       = uploaded.read()
        fname    = uploaded.name
        fsize_kb = len(fb) / 1024
        sha256   = hashlib.sha256(fb).hexdigest()

        st.session_state.file_bytes = fb
        st.session_state.filename   = fname

        st.markdown(f"""
        <div class="file-info-card">
          <div class="file-info-row">
            <span class="file-info-key">FILENAME</span>
            <span class="file-info-val">{fname}</span>
          </div>
          <div class="file-info-row">
            <span class="file-info-key">SIZE</span>
            <span class="file-info-val">
              {fsize_kb:.1f} KB</span>
          </div>
          <div class="file-info-row">
            <span class="file-info-key">SHA256</span>
            <span class="file-info-val">
              {sha256[:24]}...</span>
          </div>
          <div class="file-info-row">
            <span class="file-info-key">STATUS</span>
            <span class="status-ok">● READY</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        if st.button("◈ INITIATE SCAN",
                     use_container_width=True):
            if not check_api():
                st.error("API offline — start uvicorn")
                st.stop()

            prog   = st.progress(0)
            status = st.empty()

            steps = [
                (10,  "VALIDATING FILE HEADER..."),
                (25,  "EXTRACTING EMBER FEATURES..."),
                (45,  "SUBMITTING TO VIRUSTOTAL..."),
                (70,  "RUNNING AI MODELS..."),
                (90,  "COMPUTING WEIGHTED VOTE..."),
                (100, "ANALYSIS COMPLETE"),
            ]

            for pct, msg in steps[:-1]:
                status.markdown(f"""
                <div style="font-family:
                    var(--font-mono);
                    font-size:0.78em;
                    color:var(--cyan);
                    padding:8px 0;">
                  ▶ {msg}</div>
                """, unsafe_allow_html=True)
                prog.progress(pct)
                if pct == 45:
                    pass
                else:
                    time.sleep(0.3)

            try:
                result = analyze_file(fb, fname)
                prog.progress(100)
                status.markdown("""
                <div style="font-family:
                    var(--font-mono);
                    font-size:0.78em;
                    color:var(--green);
                    padding:8px 0;">
                  ✓ ANALYSIS COMPLETE</div>
                """, unsafe_allow_html=True)
                time.sleep(0.5)
                prog.empty()
                status.empty()

                st.session_state.result   = result
                st.session_state.analyzed = True
                st.rerun()

            except Exception as e:
                prog.empty()
                status.empty()
                st.error(f"SCAN FAILED: {e}")

    # ── Boutons action sous upload ─────────────────────
    if st.session_state.get('analyzed'):
        st.markdown("<br>", unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            if st.button("◈ NEW SCAN",
                         use_container_width=True):
                st.session_state.result   = None
                st.session_state.analyzed = False
                st.rerun()
        with c2:
            if st.button("◈ GEN REPORT",
                         use_container_width=True):
                with st.spinner("Generating PDF..."):
                    try:
                        pdf = get_report_pdf(
                            st.session_state.file_bytes,
                            st.session_state.filename)
                        st.download_button(
                            "⬇ DOWNLOAD PDF",
                            data=pdf,
                            file_name=f"f-scaner_report_{st.session_state.filename}.pdf",
                            mime="application/pdf",
                            use_container_width=True)
                    except Exception as e:
                        st.error(f"Report error: {e}")

# ── Colonne droite — Résultats ─────────────────────────────
with col_right:
    result = st.session_state.get('result')

    if not result:
        st.markdown("""
        <div style="height:300px;
                    display:flex;
                    flex-direction:column;
                    align-items:center;
                    justify-content:center;
                    border:1px dashed
                    rgba(0,212,255,0.1);
                    border-radius:4px;
                    color:rgba(0,212,255,0.2);">
          <div style="font-family:
              var(--font-display);
              font-size:3em;">⬡</div>
          <div style="font-family:
              var(--font-mono);
              font-size:0.75em;
              letter-spacing:0.1em;
              margin-top:12px;">
            AWAITING TARGET FILE</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        if 'error' in result:
            st.error(f"ERROR: {result['error']}")
        else:
            is_mal   = result.get('is_malware', False)
            conf     = result.get('confidence', 0)
            verdict  = result.get('verdict', '')
            votes    = result.get('votes', [])
            n_models = result.get('n_models', 0)
            n_mal    = result.get(
                'n_malware_votes', 0)
            dyn      = result.get(
                'dynamic_analysis', {})

            # Verdict
            st.markdown("""
            <div class="section-title">
              ◈ THREAT ASSESSMENT</div>
            """, unsafe_allow_html=True)

            if is_mal:
                st.markdown(f"""
                <div class="verdict-malware">
                  <div style="font-family:
                      var(--font-mono);
                      font-size:0.7em;
                      color:rgba(255,45,85,0.6);
                      letter-spacing:0.15em;
                      margin-bottom:8px;">
                    THREAT DETECTED</div>
                  <div class="verdict-malware-text">
                    ⚠ MALWARE</div>
                  <div style="font-family:
                      var(--font-mono);
                      font-size:0.65em;
                      color:rgba(255,45,85,0.5);
                      letter-spacing:0.1em;
                      margin-top:8px;">
                    FILE QUARANTINED — DO NOT EXECUTE
                  </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="verdict-benin">
                  <div style="font-family:
                      var(--font-mono);
                      font-size:0.7em;
                      color:rgba(0,255,136,0.5);
                      letter-spacing:0.15em;
                      margin-bottom:8px;">
                    NO THREAT DETECTED</div>
                  <div class="verdict-benin-text">
                    ✓ CLEAN</div>
                  <div style="font-family:
                      var(--font-mono);
                      font-size:0.65em;
                      color:rgba(0,255,136,0.4);
                      letter-spacing:0.1em;
                      margin-top:8px;">
                    FILE SECURED IN MINIO VAULT
                  </div>
                </div>
                """, unsafe_allow_html=True)

            # Confidence
            cls = "red" if is_mal else "green"
            clr = "var(--red)" if is_mal \
                else "var(--green)"
            st.markdown(f"""
            <div class="conf-container">
              <div class="conf-label">
                CONFIDENCE SCORE</div>
              <div class="conf-track">
                <div class="conf-fill-{cls}"
                     style="width:{conf}%"></div>
              </div>
              <div class="conf-value"
                   style="color:{clr}">
                {conf:.1f}%</div>
            </div>
            """, unsafe_allow_html=True)

            # Métriques
            mc1, mc2, mc3 = st.columns(3)
            with mc1:
                st.markdown(f"""
                <div class="metric-box">
                  <div class="metric-val">
                    {n_models}</div>
                  <div class="metric-lbl">
                    MODELS</div>
                </div>
                """, unsafe_allow_html=True)
            with mc2:
                c = "var(--red)" if n_mal >= 3 \
                    else "var(--cyan)"
                st.markdown(f"""
                <div class="metric-box">
                  <div class="metric-val"
                       style="color:{c}">
                    {n_mal}/{n_models}</div>
                  <div class="metric-lbl">
                    MAL VOTES</div>
                </div>
                """, unsafe_allow_html=True)
            with mc3:
                dyn_ok = dyn.get('available', False)
                c2     = "var(--green)" if dyn_ok \
                         else "var(--orange)"
                lbl    = "VT ✓" if dyn_ok else "VT ⚠"
                st.markdown(f"""
                <div class="metric-box">
                  <div class="metric-val"
                       style="color:{c2};
                              font-size:1.2em;">
                    {lbl}</div>
                  <div class="metric-lbl">
                    DYNAMIC</div>
                </div>
                """, unsafe_allow_html=True)

# ── Votes section ──────────────────────────────────────────
if st.session_state.get('result') and \
        'votes' in st.session_state.result:

    result = st.session_state.result
    votes  = result.get('votes', [])

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div class="section-title">
      ◈ MODEL VOTES BREAKDOWN</div>
    """, unsafe_allow_html=True)

    cols = st.columns(len(votes))
    for i, (v, col) in enumerate(
            zip(votes, cols)):
        with col:
            is_m  = v['vote'] == 'Malware'
            cls   = 'mal' if is_m else 'ben'
            icon  = '⚠' if is_m else '✓'
            label = 'THREAT' if is_m else 'CLEAN'
            st.markdown(f"""
            <div class="vote-card {cls}">
              <div class="vote-model">
                {v['model'].replace(
                    ' (statique)',''
                ).replace(' (dynamique)','')}
              </div>
              <div class="vote-verdict {cls}">
                {icon} {label}</div>
              <div class="vote-proba">
                {v['proba']:.1f}%</div>
            </div>
            """, unsafe_allow_html=True)

    # SHAP si disponible
    shap = result.get('shap_data')
    if shap and shap.get('values'):
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div class="section-title">
          ◈ SHAP FEATURE IMPORTANCE</div>
        """, unsafe_allow_html=True)

        fig = go.Figure(go.Bar(
            x=shap['values'],
            y=shap['feature_names'],
            orientation='h',
            marker=dict(
                color=shap['values'],
                colorscale=[
                    [0, '#00ff88'],
                    [0.5, '#00d4ff'],
                    [1, '#ff2d55']],
                showscale=False),
        ))
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(
                family='Share Tech Mono',
                color='#6b8aaa', size=11),
            xaxis=dict(
                gridcolor='rgba(0,212,255,0.05)',
                title='SHAP Impact'),
            yaxis=dict(
                gridcolor='rgba(0,212,255,0.05)'),
            height=280,
            margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(
            fig, use_container_width=True)

    # MinIO info
    if result.get('minio_stored') and \
            result.get('minio_object'):
        st.markdown(f"""
        <div style="background:rgba(0,255,136,0.04);
                    border:1px solid
                    rgba(0,255,136,0.2);
                    border-radius:4px;
                    padding:12px 16px;
                    font-family:var(--font-mono);
                    font-size:0.72em;
                    color:var(--green);
                    margin-top:16px;">
          ◈ SECURED IN VAULT →
          <span style="color:var(--text-dim);">
            {result['minio_object']}</span>
        </div>
        """, unsafe_allow_html=True)