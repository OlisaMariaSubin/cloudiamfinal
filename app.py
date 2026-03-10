"""
Cloud IAM Over-Permission Detection & Least-Privilege Policy Recommendation Tool
Live AWS CloudTrail — Dark Cyberpunk UI
"""

import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

from modules.log_parser import load_logs
from modules.aws_users import get_iam_users
from modules.detection_engine import (
    detect_overpermissions, generate_least_privilege_policies,
    compute_risk_summary, compute_user_risk_score,
    get_persona_summary
)
from modules.anomaly_detector import run_anomaly_detection

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IAM Shield · Over-Permission Detector",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif !important;
}

.main {
    background-color: #060810;
    background-image:
        radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,200,255,0.06) 0%, transparent 60%),
        linear-gradient(180deg, #060810 0%, #080c18 100%);
}

section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #080c18 0%, #060810 100%);
    border-right: 1px solid rgba(0,200,255,0.12);
}

section[data-testid="stSidebar"] * { color: #a0c4d8 !important; }

section[data-testid="stSidebar"] .stSelectbox label,
section[data-testid="stSidebar"] .stMultiSelect label {
    color: #4dc8e8 !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 11px !important;
    letter-spacing: 0.12em !important;
    text-transform: uppercase !important;
}

.iam-header {
    display: flex; align-items: center; gap: 20px;
    padding: 28px 0 8px 0;
    border-bottom: 1px solid rgba(0,200,255,0.15);
    margin-bottom: 28px;
}

.iam-logo {
    width: 52px; height: 52px;
    background: linear-gradient(135deg, #003a52, #006080);
    border: 1.5px solid rgba(0,200,255,0.5);
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    font-size: 26px;
    box-shadow: 0 0 24px rgba(0,200,255,0.18), inset 0 0 12px rgba(0,200,255,0.08);
}

.iam-title-block h1 {
    font-family: 'Rajdhani', sans-serif !important;
    font-size: 28px !important; font-weight: 700 !important;
    letter-spacing: 0.06em !important; color: #e4f4ff !important;
    margin: 0 !important; padding: 0 !important;
    line-height: 1.1 !important; text-transform: uppercase;
}

.iam-title-block p {
    font-family: 'Space Mono', monospace !important;
    font-size: 11px !important; color: #4dc8e8 !important;
    margin: 4px 0 0 0 !important; letter-spacing: 0.1em !important;
}

.sidebar-brand {
    font-family: 'Rajdhani', sans-serif;
    font-size: 22px; font-weight: 700; color: #e4f4ff !important;
    letter-spacing: 0.1em; text-transform: uppercase;
    display: flex; align-items: center; gap: 10px; margin-bottom: 4px;
}

.sidebar-version {
    font-family: 'Space Mono', monospace;
    font-size: 10px; color: #2a8aaa !important;
    letter-spacing: 0.15em; margin-bottom: 16px;
}

[data-testid="metric-container"] {
    background: linear-gradient(135deg, #0c1520 0%, #0a1018 100%) !important;
    border: 1px solid rgba(0,200,255,0.14) !important;
    border-radius: 10px !important;
    padding: 16px 20px !important;
    position: relative; overflow: hidden;
}

[data-testid="metric-container"]::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, transparent, rgba(0,200,255,0.6), transparent);
}

[data-testid="stMetricLabel"] {
    font-family: 'Space Mono', monospace !important;
    font-size: 10px !important; letter-spacing: 0.12em !important;
    text-transform: uppercase !important; color: #4a8ea8 !important;
}

[data-testid="stMetricValue"] {
    font-family: 'Rajdhani', sans-serif !important;
    font-size: 32px !important; font-weight: 700 !important;
    color: #00c8f0 !important; line-height: 1.1 !important;
}

[data-testid="stMetricDelta"] {
    font-family: 'Space Mono', monospace !important; font-size: 11px !important;
}

.section-title {
    font-family: 'Rajdhani', sans-serif;
    font-size: 13px; font-weight: 700; letter-spacing: 0.2em;
    text-transform: uppercase; color: #4dc8e8;
    padding: 6px 0; margin-bottom: 16px;
    border-bottom: 1px solid rgba(0,200,255,0.1);
    display: flex; align-items: center; gap: 8px;
}

.section-title::before {
    content: ''; display: inline-block;
    width: 3px; height: 16px;
    background: linear-gradient(180deg, #00c8f0, rgba(0,200,255,0.2));
    border-radius: 2px;
}

.stTabs [data-baseweb="tab-list"] {
    background: transparent !important;
    border-bottom: 1px solid rgba(0,200,255,0.12) !important;
    gap: 4px;
}

.stTabs [data-baseweb="tab"] {
    font-family: 'Rajdhani', sans-serif !important;
    font-size: 14px !important; font-weight: 600 !important;
    letter-spacing: 0.06em !important; color: #4a7a90 !important;
    background: transparent !important; border: none !important;
    padding: 10px 20px !important; border-radius: 6px 6px 0 0 !important;
    transition: all 0.2s ease !important;
}

.stTabs [data-baseweb="tab"]:hover {
    color: #a0d8ef !important; background: rgba(0,200,255,0.05) !important;
}

.stTabs [aria-selected="true"] {
    color: #00c8f0 !important;
    background: rgba(0,200,255,0.08) !important;
    border-bottom: 2px solid #00c8f0 !important;
}

[data-testid="stDataFrame"] {
    border: 1px solid rgba(0,200,255,0.1) !important;
    border-radius: 8px !important; overflow: hidden !important;
}

.stDataFrame th {
    background: #0c1824 !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 11px !important; letter-spacing: 0.08em !important;
    color: #4dc8e8 !important; text-transform: uppercase !important;
}

.stCode, [data-testid="stCode"] {
    border: 1px solid rgba(0,200,255,0.12) !important;
    border-radius: 8px !important; background: #080c14 !important;
}

.stButton > button {
    font-family: 'Rajdhani', sans-serif !important;
    font-weight: 700 !important; letter-spacing: 0.12em !important;
    text-transform: uppercase !important; font-size: 13px !important;
    background: linear-gradient(135deg, #003a52, #005570) !important;
    border: 1px solid rgba(0,200,255,0.35) !important;
    color: #00c8f0 !important; border-radius: 6px !important;
    transition: all 0.2s ease !important;
    box-shadow: 0 0 16px rgba(0,200,255,0.08) !important;
}

.stButton > button:hover {
    background: linear-gradient(135deg, #004d6e, #006d8a) !important;
    border-color: rgba(0,200,255,0.7) !important;
    box-shadow: 0 0 24px rgba(0,200,255,0.2) !important;
    transform: translateY(-1px) !important;
}

.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #005570, #007a9e) !important;
    border-color: rgba(0,200,255,0.5) !important;
    box-shadow: 0 0 20px rgba(0,200,255,0.15) !important;
}

.stSelectbox > div > div,
.stMultiSelect > div > div {
    background: #0c1520 !important;
    border: 1px solid rgba(0,200,255,0.2) !important;
    border-radius: 6px !important; color: #a0c4d8 !important;
    font-family: 'Rajdhani', sans-serif !important;
}

.stAlert {
    border-radius: 8px !important; border: 1px solid !important;
    font-family: 'Rajdhani', sans-serif !important;
    font-size: 15px !important; font-weight: 500 !important;
}

.stDownloadButton > button {
    font-family: 'Space Mono', monospace !important;
    font-size: 11px !important; letter-spacing: 0.08em !important;
    background: rgba(0,200,255,0.05) !important;
    border: 1px solid rgba(0,200,255,0.25) !important;
    color: #4dc8e8 !important; border-radius: 6px !important;
}

.stCaption, [data-testid="stCaptionContainer"] {
    font-family: 'Space Mono', monospace !important;
    font-size: 11px !important; color: #2e6a80 !important;
    letter-spacing: 0.06em !important;
}

.stSpinner { color: #00c8f0 !important; }

hr { border-color: rgba(0,200,255,0.1) !important; margin: 20px 0 !important; }

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #060810; }
::-webkit-scrollbar-thumb { background: rgba(0,200,255,0.25); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(0,200,255,0.45); }

.main::after {
    content: ''; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
        0deg, transparent, transparent 2px,
        rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px
    );
    pointer-events: none; z-index: 9999;
}

.sidebar-stat {
    background: rgba(0,200,255,0.04);
    border: 1px solid rgba(0,200,255,0.1);
    border-radius: 6px; padding: 10px 14px; margin: 6px 0;
    font-family: 'Space Mono', monospace; font-size: 11px; color: #4a8ea8;
}

.sidebar-stat strong { color: #00c8f0 !important; float: right; }

h3 {
    font-family: 'Rajdhani', sans-serif !important;
    font-size: 20px !important; font-weight: 700 !important;
    letter-spacing: 0.08em !important; color: #c8e8f4 !important;
    text-transform: uppercase !important; margin-bottom: 4px !important;
}

p, li {
    font-family: 'Rajdhani', sans-serif !important;
    font-size: 15px !important; color: #7aa8be !important;
}

.js-plotly-plot { border-radius: 10px !important; overflow: hidden !important; }
</style>
""", unsafe_allow_html=True)

# ── Plotly dark theme ─────────────────────────────────────────────────────────
PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(6,8,16,0)",
    plot_bgcolor="rgba(10,16,26,0.6)",
    font=dict(family="Rajdhani, sans-serif", color="#7aa8be", size=13),
    title_font=dict(family="Rajdhani, sans-serif", color="#c8e8f4", size=16),
    xaxis=dict(
        gridcolor="rgba(0,200,255,0.06)", linecolor="rgba(0,200,255,0.1)",
        tickfont=dict(family="Space Mono, monospace", size=10, color="#2e6a80"),
        title_font=dict(family="Rajdhani", color="#4a8ea8")
    ),
    yaxis=dict(
        gridcolor="rgba(0,200,255,0.06)", linecolor="rgba(0,200,255,0.1)",
        tickfont=dict(family="Space Mono, monospace", size=10, color="#2e6a80"),
        title_font=dict(family="Rajdhani", color="#4a8ea8")
    ),
    legend=dict(
        bgcolor="rgba(6,8,16,0.7)", bordercolor="rgba(0,200,255,0.12)",
        borderwidth=1, font=dict(family="Rajdhani", size=12)
    ),
    margin=dict(t=48, b=36, l=40, r=20),
)

SEVERITY_COLORS_DARK = {
    "Critical": "#ff3c3c",
    "High":     "#40394b",
    "Medium":   "#f5c518",
    "Low":      "#00e676",
}


# ── Cache ─────────────────────────────────────────────────────────────────────
@st.cache_data(ttl=300)
def cached_logs(days, username):
    return load_logs(days=days, username=username)


# ── Session State + Auth Gate ─────────────────────────────────────────────────
if "authenticated" not in st.session_state: st.session_state.authenticated = False
if "username"      not in st.session_state: st.session_state.username      = ""
if "analyzed"      not in st.session_state: st.session_state.analyzed      = False

if not st.session_state.authenticated:
    st.switch_page("pages/login.py")

uname = st.session_state.get("username", "")


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="sidebar-brand">🛡 IAM Shield</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-version">v2.1 · LIVE AWS CLOUDTRAIL</div>', unsafe_allow_html=True)

    st.markdown(f"""
    <div class="sidebar-stat" style="margin-bottom:4px;">
        USER &nbsp;<strong>{uname.upper()}</strong>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown("""
    <div style="font-family:'Space Mono',monospace;font-size:10px;color:#2e6a80;
    letter-spacing:0.15em;text-transform:uppercase;margin-bottom:10px;">
    ◈ CONFIGURATION
    </div>""", unsafe_allow_html=True)

    # Live IAM users from AWS
    try:
        iam_users = get_iam_users()
    except Exception as e:
        st.error(f"Unable to fetch IAM users: {e}")
        iam_users = []

    selected_user = st.selectbox(
        "Filter by User",
        ["All Users"] + iam_users
    )

    selected_days = st.slider(
        "Days of Logs",
        min_value=1,
        max_value=30,
        value=7
    )

    severity_filter = st.multiselect(
        "Severity Filter",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )

    st.markdown("---")
    run_btn = st.button("⬡  Run Analysis", use_container_width=True, type="primary")
    st.markdown("---")

    st.markdown("""
    <div class="sidebar-stat">Source <strong>AWS CloudTrail</strong></div>
    <div class="sidebar-stat">Format <strong>Live API</strong></div>
    <div class="sidebar-stat">Engine <strong>Isolation Forest</strong></div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    if st.button("⬡  Sign Out", use_container_width=True, key="signout_btn"):
        st.session_state.authenticated = False
        st.session_state.username      = ""
        st.session_state.analyzed      = False
        st.switch_page("pages/login.py")

    st.markdown("""
    <div style="margin-top:16px;font-family:'Space Mono',monospace;font-size:10px;
    color:#1e4a5a;letter-spacing:0.08em;text-align:center;line-height:1.8;">
    LIVE AWS CLOUDTRAIL TELEMETRY<br>
    AUTOMATED LEAST-PRIVILEGE ANALYSIS
    </div>""", unsafe_allow_html=True)


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="iam-header">
  <div class="iam-logo">☁️</div>
  <div class="iam-title-block">
    <h1>IAM Over-Permission Detector</h1>
    <p>AUTOMATED LEAST-PRIVILEGE ANALYSIS · LIVE AWS CLOUDTRAIL · {uname.upper()}</p>
  </div>
</div>
""", unsafe_allow_html=True)


# ── Session state ─────────────────────────────────────────────────────────────
if run_btn:
    st.session_state.analyzed      = True
    st.session_state.selected_days = selected_days
    st.session_state.selected_user = selected_user

if not st.session_state.analyzed:
    st.markdown("""
    <div style="
        background: linear-gradient(135deg, #080e1c, #0a1224);
        border: 1px solid rgba(0,200,255,0.15);
        border-radius: 12px; padding: 40px;
        text-align: center; margin: 40px 0;
    ">
        <div style="font-size:48px;margin-bottom:16px;">🔍</div>
        <div style="font-family:'Rajdhani',sans-serif;font-size:22px;font-weight:700;
            color:#c8e8f4;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:10px;">
            Ready to Scan
        </div>
        <div style="font-family:'Space Mono',monospace;font-size:12px;color:#2e6a80;
            letter-spacing:0.08em;">
            Configure options in the sidebar and click
            <span style='color:#00c8f0'>RUN ANALYSIS</span> to begin
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()


# ── Load logs (live AWS) ──────────────────────────────────────────────────────
days_to_load  = st.session_state.get("selected_days", 7)
active_user   = st.session_state.get("selected_user", "All Users")

with st.spinner(f"Loading live CloudTrail logs · Last {days_to_load} day(s)…"):
    try:
        logs_df = cached_logs(
            days=days_to_load,
            username=None if active_user == "All Users" else active_user
        )
    except Exception as e:
        st.error(f"AWS error: {e}")
        st.stop()

if logs_df.empty:
    st.warning("No logs found for the selected filters.")
    st.stop()


# ── Run analysis ──────────────────────────────────────────────────────────────
with st.spinner("Running IAM analysis…"):
    findings_df     = detect_overpermissions(logs_df)
    policies_rec    = generate_least_privilege_policies(logs_df)
    anomalies_df    = run_anomaly_detection(logs_df)
    risk_summary    = compute_risk_summary(findings_df)
    user_risk_df    = compute_user_risk_score(findings_df)
    persona_summary = get_persona_summary(logs_df)


# ── Apply filters ─────────────────────────────────────────────────────────────
filtered_findings = findings_df[findings_df["Severity"].isin(severity_filter)]
if active_user != "All Users":
    filtered_findings = filtered_findings[filtered_findings["User"] == active_user]


# ── KPI Cards ─────────────────────────────────────────────────────────────────
st.markdown("""
<div style="font-family:'Space Mono',monospace;font-size:11px;color:#2e6a80;
letter-spacing:0.2em;text-transform:uppercase;margin-bottom:14px;">
◈ SYSTEM OVERVIEW
</div>""", unsafe_allow_html=True)

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Days Analysed",      days_to_load)
col2.metric("Total Events",       f"{len(logs_df):,}")
col3.metric("🔴 Critical Issues", risk_summary["Critical"])
col4.metric("🟠 High Issues",     risk_summary["High"])
col5.metric("Unused Permissions", len(findings_df))

st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

# Threat pulse bar
total_issues = sum(risk_summary.values())
critical_pct = int(risk_summary["Critical"] / max(total_issues, 1) * 100)
high_pct     = int(risk_summary["High"]     / max(total_issues, 1) * 100)
med_pct      = int(risk_summary["Medium"]   / max(total_issues, 1) * 100)
low_pct      = max(0, 100 - critical_pct - high_pct - med_pct)
st.markdown(f"""
<div style="margin:8px 0 24px 0;">
  <div style="font-family:'Space Mono',monospace;font-size:10px;color:#2e6a80;
       letter-spacing:0.15em;margin-bottom:8px;">THREAT DISTRIBUTION</div>
  <div style="display:flex;height:6px;border-radius:3px;overflow:hidden;gap:2px;">
    <div style="flex:{critical_pct};background:#ff3c3c;border-radius:2px;"></div>
    <div style="flex:{high_pct};background:#40394b;border-radius:2px;"></div>
    <div style="flex:{med_pct};background:#f5c518;border-radius:2px;"></div>
    <div style="flex:{low_pct};background:#00e676;border-radius:2px;"></div>
  </div>
  <div style="display:flex;gap:20px;margin-top:6px;">
    <span style="font-family:'Space Mono',monospace;font-size:10px;color:#ff3c3c;">■ Critical {risk_summary['Critical']}</span>
    <span style="font-family:'Space Mono',monospace;font-size:10px;color:#40394b;">■ High {risk_summary['High']}</span>
    <span style="font-family:'Space Mono',monospace;font-size:10px;color:#f5c518;">■ Medium {risk_summary['Medium']}</span>
    <span style="font-family:'Space Mono',monospace;font-size:10px;color:#00e676;">■ Low {risk_summary['Low']}</span>
  </div>
</div>
""", unsafe_allow_html=True)


# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📋  Over-Permission Report",
    "📊  Risk Dashboard",
    "🤖  ML Anomaly Detection",
    "🛡️  Policy Recommendations",
    "📁  Raw Logs",
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — Over-Permission Report
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown('<div class="section-title">Detected Over-Permissions</div>', unsafe_allow_html=True)
    st.caption(f"Showing {len(filtered_findings)} findings · Last {days_to_load} day(s)")

    if filtered_findings.empty:
        st.success("✓  No findings with current filters.")
    else:
        ft_counts = filtered_findings["FindingType"].value_counts()
        c1, c2, c3 = st.columns(3)
        c1.metric("🚨 Unauthorized Actions",     ft_counts.get("Unauthorized Action 🚨", 0))
        c2.metric("⚠️ Over-Perms Actively Used", ft_counts.get("Over-Permission (Actively Used) ⚠️", 0))
        c3.metric("💤 Over-Perms Never Used",    ft_counts.get("Over-Permission (Unused)", 0))

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        BADGES = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        display_df = filtered_findings.copy()
        display_df["Severity"] = display_df["Severity"].apply(
            lambda s: f"{BADGES.get(s, '⚪')} {s}"
        )
        st.dataframe(
            display_df[["User", "Role", "Service", "Permission", "Severity", "FindingType", "Recommendation"]],
            use_container_width=True, height=420
        )
        csv = filtered_findings.to_csv(index=False)
        st.download_button(
            "⬇  Download Report (CSV)", data=csv,
            file_name=f"iam_report_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv"
        )

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    st.markdown('<div class="section-title">User Permission Summary</div>', unsafe_allow_html=True)
    st.dataframe(persona_summary, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — Risk Dashboard
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown('<div class="section-title">Risk Dashboard</div>', unsafe_allow_html=True)

    col_l, col_r = st.columns(2)

    with col_l:
        sev_data = pd.DataFrame([
            {"Severity": k, "Count": v} for k, v in risk_summary.items() if v > 0
        ])
        if not sev_data.empty:
            fig_pie = go.Figure(go.Pie(
                labels=sev_data["Severity"],
                values=sev_data["Count"],
                hole=0.55,
                marker=dict(
                    colors=[SEVERITY_COLORS_DARK.get(s, "#888") for s in sev_data["Severity"]],
                    line=dict(color="#060810", width=3)
                ),
                textfont=dict(family="Rajdhani, sans-serif", size=13),
            ))
            fig_pie.add_annotation(
                text=f"<b>{total_issues}</b><br><span style='font-size:11px'>ISSUES</span>",
                x=0.5, y=0.5, showarrow=False,
                font=dict(family="Rajdhani, sans-serif", size=20, color="#c8e8f4")
            )
            fig_pie.update_layout(title="Permissions by Severity", showlegend=True, **PLOTLY_LAYOUT)
            st.plotly_chart(fig_pie, use_container_width=True)

    with col_r:
        if not user_risk_df.empty:
            colors = [SEVERITY_COLORS_DARK.get(lvl, "#888") for lvl in user_risk_df["RiskLevel"]]
            fig_bar = go.Figure(go.Bar(
                x=user_risk_df["User"], y=user_risk_df["RiskScore"],
                text=user_risk_df["RiskScore"], textposition="outside",
                marker=dict(color=colors, line=dict(color="rgba(0,200,255,0.2)", width=1)),
                textfont=dict(family="Space Mono, monospace", size=11),
            ))
            fig_bar.update_layout(title="User Risk Scores (0–100)", **PLOTLY_LAYOUT)
            st.plotly_chart(fig_bar, use_container_width=True)

    if not findings_df.empty:
        svc_counts = findings_df.groupby(["Service", "Severity"]).size().reset_index(name="Count")
        fig_svc = px.bar(
            svc_counts, x="Service", y="Count", color="Severity",
            title="Over-Permissions by AWS Service",
            color_discrete_map=SEVERITY_COLORS_DARK, barmode="stack"
        )
        fig_svc.update_layout(**PLOTLY_LAYOUT)
        fig_svc.update_traces(marker_line_color="rgba(0,200,255,0.15)", marker_line_width=0.5)
        st.plotly_chart(fig_svc, use_container_width=True)

    if not logs_df.empty and "user" in logs_df.columns and "eventTime" in logs_df.columns:
        logs_df["_date"] = pd.to_datetime(logs_df["eventTime"]).dt.date
        daily = logs_df.groupby(["_date", "user"]).size().reset_index(name="Actions")
        daily.rename(columns={"_date": "Date"}, inplace=True)
        fig_daily = px.bar(
            daily, x="Date", y="Actions", color="user",
            title="Daily Activity per User", barmode="group"
        )
        fig_daily.update_layout(**PLOTLY_LAYOUT)
        st.plotly_chart(fig_daily, use_container_width=True)

    st.markdown('<div class="section-title">User Risk Leaderboard</div>', unsafe_allow_html=True)
    if not user_risk_df.empty:
        st.dataframe(
            user_risk_df[["User","RiskScore","RiskLevel","ThreatLabel","ActiveMisuse","UnauthorizedActions","TotalFindings"]],
            use_container_width=True
        )


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — ML Anomaly Detection
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown('<div class="section-title">ML-Based Behavioral Anomaly Detection</div>', unsafe_allow_html=True)
    st.caption("Isolation Forest on live AWS CloudTrail activity patterns")

    if anomalies_df.empty:
        st.warning("Not enough user data for anomaly detection.")
    else:
        flagged = anomalies_df[anomalies_df["IsAnomaly"]]
        normal  = anomalies_df[~anomalies_df["IsAnomaly"]]

        c1, c2 = st.columns(2)
        c1.metric("🚨 Anomalous Users", len(flagged))
        c2.metric("✓ Normal Users",     len(normal))

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        st.markdown('<div class="section-title">Flagged Users</div>', unsafe_allow_html=True)

        if not flagged.empty:
            disp = flagged[[
                "user","SuspicionScore","failure_rate","iam_ratio",
                "destructive_count","overperm_rate","AnomalyReason"
            ]].copy()
            disp.columns = ["User","Suspicion Score","Failure Rate","IAM Ratio",
                            "Destructive Actions","OverPerm Rate","Reason"]
            st.dataframe(disp, use_container_width=True)
        else:
            st.success("✓  No anomalous users detected.")

        fig_anom = go.Figure()
        for is_anom, label, color, symbol in [
            (False, "Normal",    "#00c8f0", "circle"),
            (True,  "Anomalous", "#ff3c3c", "diamond"),
        ]:
            subset = anomalies_df[anomalies_df["IsAnomaly"] == is_anom]
            if not subset.empty:
                fig_anom.add_trace(go.Scatter(
                    x=subset["failure_rate"], y=subset["iam_ratio"],
                    mode="markers", name=label,
                    marker=dict(
                        size=subset["SuspicionScore"].clip(lower=6),
                        color=color, symbol=symbol,
                        line=dict(color="rgba(0,200,255,0.3)", width=1),
                        opacity=0.85
                    ),
                    text=subset["user"],
                    customdata=subset[["SuspicionScore","AnomalyReason"]],
                    hovertemplate=(
                        "<b>%{text}</b><br>Failure Rate: %{x:.2f}<br>"
                        "IAM Ratio: %{y:.2f}<br>Suspicion: %{customdata[0]}<br>"
                        "Reason: %{customdata[1]}<extra></extra>"
                    )
                ))

        fig_anom.update_layout(
            title="Anomaly Map: Failure Rate vs IAM Activity",
            xaxis_title="Failure Rate", yaxis_title="IAM Action Ratio",
            **PLOTLY_LAYOUT
        )
        st.plotly_chart(fig_anom, use_container_width=True)

        st.markdown('<div class="section-title">All Users — Behavioral Features</div>', unsafe_allow_html=True)
        st.dataframe(anomalies_df[[
            "user","total_actions","unique_actions","unique_services",
            "failure_rate","iam_ratio","destructive_count",
            "overperm_rate","SuspicionScore","IsAnomaly"
        ]], use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — Policy Recommendations
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown('<div class="section-title">Least-Privilege Policy Recommendations</div>', unsafe_allow_html=True)
    st.caption(f"Based on permissions actually used in the last {days_to_load} day(s)")

    user_select = st.selectbox("Select User", list(policies_rec.keys()))

    if user_select:
        rec = policies_rec[user_select]

        # Support both dict formats (with or without "meta" key)
        if "meta" in rec:
            meta = rec["meta"]
            c1, c2, c3 = st.columns(3)
            c1.metric("Original Permissions",    meta["OriginalPermissions"])
            c2.metric("Recommended Permissions", meta["RecommendedPermissions"])
            c3.metric(
                "Permission Reduction", f"{meta['ReductionPercent']}%",
                delta=f"−{meta['PermissionsRemoved']} removed", delta_color="inverse"
            )
            st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
            col_orig, col_new = st.columns(2)
            with col_orig:
                st.markdown("""
                <div style="font-family:'Space Mono',monospace;font-size:11px;color:#40394b;
                letter-spacing:0.12em;margin-bottom:8px;">⚠  CURRENT POLICY (OVER-PERMISSIONED)</div>
                """, unsafe_allow_html=True)
                st.code(json.dumps(rec["original"], indent=2), language="json")
            with col_new:
                st.markdown("""
                <div style="font-family:'Space Mono',monospace;font-size:11px;color:#00e676;
                letter-spacing:0.12em;margin-bottom:8px;">✓  RECOMMENDED LEAST-PRIVILEGE POLICY</div>
                """, unsafe_allow_html=True)
                st.code(json.dumps(rec["recommended"], indent=2), language="json")
        else:
            st.code(json.dumps(rec["recommended"], indent=2), language="json")

        st.download_button(
            f"⬇  Download Recommended Policy — {user_select}",
            data=json.dumps(rec["recommended"], indent=2),
            file_name=f"least_privilege_{user_select}_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json"
        )


# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — Raw Logs
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.markdown('<div class="section-title">CloudTrail Raw Logs</div>', unsafe_allow_html=True)
    st.caption(f"Live AWS CloudTrail · Last {days_to_load} day(s)")

    available_users   = ["All"] + sorted(logs_df["user"].unique().tolist()) if "user" in logs_df.columns else ["All"]
    available_statuses = ["All", "Success", "Failed"]

    c1, c2 = st.columns(2)
    log_user_filter   = c1.selectbox("Filter by User",   available_users,   key="lf_user")
    log_status_filter = c2.selectbox("Filter by Status", available_statuses, key="lf_status")

    filtered_logs = logs_df.copy()
    if log_user_filter   != "All" and "user"   in filtered_logs.columns:
        filtered_logs = filtered_logs[filtered_logs["user"]   == log_user_filter]
    if log_status_filter != "All" and "status" in filtered_logs.columns:
        filtered_logs = filtered_logs[filtered_logs["status"] == log_status_filter]

    st.caption(f"Showing {len(filtered_logs):,} of {len(logs_df):,} events")
    st.dataframe(
        filtered_logs.sort_values("eventTime", ascending=False).head(500),
        use_container_width=True, height=430
    )

    if "isOverPermission" in filtered_logs.columns:
        st.markdown('<div class="section-title">Over-Permission Events</div>', unsafe_allow_html=True)
        overperm_logs = filtered_logs[filtered_logs["isOverPermission"] == True]
        st.caption(f"{len(overperm_logs)} over-permission events in current filter")
        if not overperm_logs.empty:
            st.dataframe(overperm_logs.sort_values("eventTime"), use_container_width=True, height=280)

    # Activity timeline
    if "user" in logs_df.columns and "eventTime" in logs_df.columns:
        logs_df["_date"] = pd.to_datetime(logs_df["eventTime"]).dt.date
        timeline = logs_df.groupby(["_date","user"]).size().reset_index(name="Actions")
        timeline.rename(columns={"_date": "Date"}, inplace=True)
        fig_tl = px.line(
            timeline, x="Date", y="Actions", color="user",
            title="Daily Action Timeline per User", markers=True
        )
        fig_tl.update_traces(line=dict(width=2))
        fig_tl.update_layout(**PLOTLY_LAYOUT)
        st.plotly_chart(fig_tl, use_container_width=True)