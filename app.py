"""
Cloud IAM Over-Permission Detection & Least-Privilege Policy Recommendation Tool
Streamlit Dashboard — powered by real CloudTrail logs from logs/day*_logs.json
"""

import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

from modules.log_parser import load_logs
from modules.detection_engine import (
    detect_overpermissions, generate_least_privilege_policies,
    compute_risk_summary, compute_user_risk_score,
    get_persona_summary, SEVERITY_COLORS, REAL_IAM_POLICIES
)
from modules.anomaly_detector import run_anomaly_detection

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IAM Over-Permission Detector",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #0f1117; }
    .stTabs [data-baseweb="tab"] { font-size: 15px; font-weight: 600; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🔐 IAM Audit Tool")
    st.markdown("---")
    st.markdown("**Configuration**")

    # Day selector — the actual meaningful filter
    selected_days = st.multiselect(
        "Select Days to Analyse",
        options=[1, 2, 3, 4, 5, 6],
        default=[1, 2, 3, 4, 5, 6],
        format_func=lambda d: f"Day {d} (Mar {d+2}, 2026)"
    )

    selected_user = st.selectbox(
        "Filter by User",
        ["All Users"] + list(REAL_IAM_POLICIES.keys())
    )

    severity_filter = st.multiselect(
        "Severity Filter",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )

    st.markdown("---")
    run_btn = st.button("🔍 Run Analysis", use_container_width=True, type="primary")
    st.markdown("---")
    st.caption("Real CloudTrail logs from logs/day*_logs.json")

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("# ☁️ Cloud IAM Over-Permission Detection Tool")
st.markdown("**Automated least-privilege analysis powered by real CloudTrail logs**")
st.markdown("---")

# ── Session state ─────────────────────────────────────────────────────────────
if "analyzed" not in st.session_state:
    st.session_state.analyzed = False

if run_btn:
    st.session_state.analyzed = True
    st.session_state.selected_days = selected_days

if not st.session_state.analyzed:
    st.info("Select the days you want to analyse in the sidebar, then click **Run Analysis**.")
    st.stop()

# ── Load logs for selected days ───────────────────────────────────────────────
days_to_load = st.session_state.get("selected_days", list(range(1, 7)))
if not days_to_load:
    st.warning("Please select at least one day.")
    st.stop()

with st.spinner(f"Loading logs for Day(s): {days_to_load} ..."):
    try:
        logs_df = load_logs(logs_dir="logs", selected_days=days_to_load)
    except FileNotFoundError as e:
        st.error(str(e))
        st.stop()

if logs_df.empty:
    st.error("No log data found for the selected days.")
    st.stop()

# ── Run analysis ──────────────────────────────────────────────────────────────
with st.spinner("Running IAM analysis..."):
    findings_df    = detect_overpermissions(logs_df)
    policies_rec   = generate_least_privilege_policies(logs_df)
    anomalies_df   = run_anomaly_detection(logs_df)
    risk_summary   = compute_risk_summary(findings_df)
    user_risk_df   = compute_user_risk_score(findings_df)
    persona_summary = get_persona_summary(logs_df)

# ── Apply sidebar filters ─────────────────────────────────────────────────────
filtered_findings = findings_df[findings_df["Severity"].isin(severity_filter)]
if selected_user != "All Users":
    filtered_findings = filtered_findings[filtered_findings["User"] == selected_user]

# ── KPI Cards ─────────────────────────────────────────────────────────────────
st.markdown("### Overview")
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Days Analysed",       len(days_to_load))
col2.metric("Total Events",        f"{len(logs_df):,}")
col3.metric("Critical Issues",     risk_summary["Critical"])
col4.metric("High Issues",         risk_summary["High"])
col5.metric("Unused Permissions",  len(findings_df))
st.markdown("---")

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📋 Over-Permission Report",
    "📊 Risk Dashboard",
    "🤖 ML Anomaly Detection",
    "🛡️ Policy Recommendations",
    "📁 Raw Logs",
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — Over-Permission Report
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("### Detected Over-Permissions")
    st.caption(f"Showing {len(filtered_findings)} findings · Days: {days_to_load}")

    if filtered_findings.empty:
        st.success("No findings with current filters!")
    else:
        # Summary counts by finding type
        ft_counts = filtered_findings["FindingType"].value_counts()
        c1, c2, c3 = st.columns(3)
        c1.metric("🚨 Unauthorized Actions",          ft_counts.get("Unauthorized Action 🚨", 0))
        c2.metric("⚠️ Over-Perms Actively Used",      ft_counts.get("Over-Permission (Actively Used) ⚠️", 0))
        c3.metric("💤 Over-Perms Never Used",         ft_counts.get("Over-Permission (Unused)", 0))
        st.markdown("")

        BADGES = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        display_df = filtered_findings.copy()
        display_df["Severity"] = display_df["Severity"].apply(
            lambda s: f"{BADGES.get(s, '⚪')} {s}"
        )
        st.dataframe(
            display_df[["User", "Role", "Service", "Permission", "Severity", "FindingType", "Recommendation"]],
            use_container_width=True, height=440
        )
        csv = filtered_findings.to_csv(index=False)
        st.download_button(
            "⬇️ Download Report (CSV)", data=csv,
            file_name=f"iam_report_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv"
        )

    st.markdown("### 👥 User Permission Summary")
    st.dataframe(persona_summary, use_container_width=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — Risk Dashboard
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### Risk Dashboard")

    col_l, col_r = st.columns(2)

    with col_l:
        sev_data = pd.DataFrame([
            {"Severity": k, "Count": v} for k, v in risk_summary.items() if v > 0
        ])
        if not sev_data.empty:
            fig_pie = px.pie(
                sev_data, values="Count", names="Severity",
                title="Unused Permissions by Severity",
                color="Severity", color_discrete_map=SEVERITY_COLORS, hole=0.4
            )
            fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig_pie, use_container_width=True)

    with col_r:
        if not user_risk_df.empty:
            fig_bar = px.bar(
                user_risk_df, x="User", y="RiskScore", color="RiskLevel",
                color_discrete_map=SEVERITY_COLORS,
                title="User Risk Scores (0–100)", text="RiskScore"
            )
            fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig_bar, use_container_width=True)

    if not findings_df.empty:
        svc_counts = findings_df.groupby(["Service", "Severity"]).size().reset_index(name="Count")
        fig_svc = px.bar(
            svc_counts, x="Service", y="Count", color="Severity",
            title="Over-Permissions by AWS Service",
            color_discrete_map=SEVERITY_COLORS, barmode="stack"
        )
        fig_svc.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig_svc, use_container_width=True)

    # Daily event volume
    if not logs_df.empty:
        daily = logs_df.groupby(['day', 'user']).size().reset_index(name='Actions')
        daily['Date'] = daily['day'].apply(lambda d: f"Day {d} (Mar {d+2})")
        fig_daily = px.bar(
            daily, x="Date", y="Actions", color="user",
            title="Daily Activity per User", barmode="group"
        )
        fig_daily.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig_daily, use_container_width=True)

    st.markdown("### User Risk Leaderboard")
    if not user_risk_df.empty:
        st.dataframe(user_risk_df[["User","RiskScore","RiskLevel","ThreatLabel","ActiveMisuse","UnauthorizedActions","TotalFindings"]], use_container_width=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — ML Anomaly Detection
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### ML-Based Behavioral Anomaly Detection")
    st.caption("Using **Isolation Forest** on real activity patterns from your CloudTrail logs")

    if anomalies_df.empty:
        st.warning("Not enough user data for anomaly detection.")
    else:
        flagged = anomalies_df[anomalies_df["IsAnomaly"]]
        normal  = anomalies_df[~anomalies_df["IsAnomaly"]]

        c1, c2 = st.columns(2)
        c1.metric("Anomalous Users", len(flagged))
        c2.metric("Normal Users",    len(normal))

        st.markdown("#### 🚨 Flagged Users")
        if not flagged.empty:
            disp = flagged[[
                "user", "SuspicionScore", "failure_rate", "iam_ratio",
                "destructive_count", "overperm_rate", "AnomalyReason"
            ]].copy()
            disp.columns = [
                "User", "Suspicion Score", "Failure Rate", "IAM Ratio",
                "Destructive Actions", "OverPerm Rate", "Reason"
            ]
            st.dataframe(disp, use_container_width=True)
        else:
            st.success("No anomalous users detected!")

        fig_anom = px.scatter(
            anomalies_df,
            x="failure_rate", y="iam_ratio",
            size="SuspicionScore", color="IsAnomaly",
            hover_data=["user", "SuspicionScore", "AnomalyReason"],
            title="Anomaly Map: Failure Rate vs IAM Activity",
            labels={"failure_rate": "Failure Rate", "iam_ratio": "IAM Action Ratio",
                    "IsAnomaly": "Anomalous"},
            color_discrete_map={True: "#FF4B4B", False: "#00C49F"}
        )
        fig_anom.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig_anom, use_container_width=True)

        st.markdown("#### All Users — Behavioral Features")
        st.dataframe(anomalies_df[[
            "user", "total_actions", "unique_actions", "unique_services",
            "failure_rate", "iam_ratio", "destructive_count",
            "overperm_rate", "SuspicionScore", "IsAnomaly"
        ]], use_container_width=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — Policy Recommendations
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown("### 🛡️ Least-Privilege Policy Recommendations")
    st.caption("Based on permissions actually used in the selected days")

    user_select = st.selectbox("Select User", list(policies_rec.keys()))

    if user_select:
        rec  = policies_rec[user_select]
        meta = rec["meta"]

        c1, c2, c3 = st.columns(3)
        c1.metric("Original Permissions",    meta["OriginalPermissions"])
        c2.metric("Recommended Permissions", meta["RecommendedPermissions"])
        c3.metric("Reduction",               f"{meta['ReductionPercent']}%",
                  delta=f"-{meta['PermissionsRemoved']} permissions",
                  delta_color="inverse")

        col_orig, col_new = st.columns(2)
        with col_orig:
            st.markdown("#### ⚠️ Current Policy (Over-Permissioned)")
            st.code(json.dumps(rec["original"], indent=2), language="json")
        with col_new:
            st.markdown("#### ✅ Recommended Least-Privilege Policy")
            st.code(json.dumps(rec["recommended"], indent=2), language="json")

        st.download_button(
            f"⬇️ Download Recommended Policy for {user_select}",
            data=json.dumps(rec["recommended"], indent=2),
            file_name=f"least_privilege_{user_select}_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json"
        )

# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — Raw Logs
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.markdown("### 📁 CloudTrail Logs")
    st.caption(f"Loaded from logs/day*_logs.json · Days: {days_to_load}")

    c1, c2, c3 = st.columns(3)
    log_user_filter   = c1.selectbox("Filter by User",   ["All"] + sorted(logs_df["user"].unique().tolist()),   key="lf_user")
    log_status_filter = c2.selectbox("Filter by Status", ["All", "Success", "Failed"], key="lf_status")
    log_day_filter    = c3.selectbox("Filter by Day",    ["All"] + [f"Day {d}" for d in sorted(logs_df["day"].unique())], key="lf_day")

    filtered_logs = logs_df.copy()
    if log_user_filter   != "All":
        filtered_logs = filtered_logs[filtered_logs["user"] == log_user_filter]
    if log_status_filter != "All":
        filtered_logs = filtered_logs[filtered_logs["status"] == log_status_filter]
    if log_day_filter    != "All":
        day_num = int(log_day_filter.replace("Day ", ""))
        filtered_logs = filtered_logs[filtered_logs["day"] == day_num]

    st.caption(f"Showing {len(filtered_logs):,} of {len(logs_df):,} events")
    st.dataframe(
        filtered_logs[[
            "eventTime", "day", "user", "service", "eventName",
            "status", "isOverPermission", "description"
        ]].sort_values("eventTime", ascending=False).head(500),
        use_container_width=True, height=450
    )

    # Over-permission events highlighted
    st.markdown("#### 🚨 Over-Permission Events")
    overperm_logs = filtered_logs[filtered_logs["isOverPermission"] == True]
    st.caption(f"{len(overperm_logs)} over-permission events in current filter")
    if not overperm_logs.empty:
        st.dataframe(
            overperm_logs[["eventTime", "day", "user", "eventName", "status", "description"]]
            .sort_values("eventTime"),
            use_container_width=True, height=300
        )

    # Timeline
    timeline = logs_df.groupby(["day", "user"]).size().reset_index(name="Actions")
    timeline["Date"] = timeline["day"].apply(lambda d: f"Day {d}")
    fig_tl = px.line(
        timeline, x="Date", y="Actions", color="user",
        title="Daily Action Timeline per User", markers=True
    )
    fig_tl.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig_tl, use_container_width=True)
