# ShadowTrace - Module 4: Investigation Dashboard
# Interactive web dashboard for forensic analysis results

import streamlit as st
import json
import os
import plotly.express as px
import pandas as pd

st.set_page_config(
    page_title="ShadowTrace - Forensic Dashboard",
    page_icon="🕵️",
    layout="wide"
)

def load_alerts(filepath):
    """Load alerts from JSON report file"""
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return []

# Load all module alerts
network_alerts = load_alerts('reports/network_alerts.json')
antiforensics_alerts = load_alerts('reports/antiforensics_alerts.json')
artifact_alerts = load_alerts('reports/artifact_alerts.json')
all_alerts = network_alerts + antiforensics_alerts + artifact_alerts

# ── Header ──────────────────────────────────────────
st.title("🕵️ ShadowTrace — Forensic Investigation Dashboard")
st.markdown("**Case:** Unauthorized Web Activity & Anti-Forensics Behavior")
st.divider()

# ── KPI Cards ───────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)

high_alerts = [a for a in all_alerts if a.get('severity') == 'HIGH']
med_alerts  = [a for a in all_alerts if a.get('severity') == 'MEDIUM']

with col1:
    st.metric("🚨 Total Alerts", len(all_alerts))
with col2:
    st.metric("🔴 High Severity", len(high_alerts))
with col3:
    st.metric("🟡 Medium Severity", len(med_alerts))
with col4:
    st.metric("📁 Modules Run", 3)

st.divider()

# ── Charts ──────────────────────────────────────────
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("📊 Alerts by Type")
    if all_alerts:
        df = pd.DataFrame(all_alerts)
        type_counts = df['type'].value_counts().reset_index()
        type_counts.columns = ['Alert Type', 'Count']
        fig = px.bar(type_counts, x='Alert Type', y='Count',
                     color='Count', color_continuous_scale='reds')
        st.plotly_chart(fig, use_container_width=True)

with col_right:
    st.subheader("🔴 Alerts by Severity")
    if all_alerts:
        sev_counts = df['severity'].value_counts().reset_index()
        sev_counts.columns = ['Severity', 'Count']
        colors = {'HIGH': '#ff4444', 'MEDIUM': '#ffaa00'}
        fig2 = px.pie(sev_counts, names='Severity', values='Count',
                      color='Severity', color_discrete_map=colors)
        st.plotly_chart(fig2, use_container_width=True)

st.divider()

# ── Alert Tables ─────────────────────────────────────
st.subheader("🌐 Module 1 — Network Alerts")
if network_alerts:
    st.dataframe(pd.DataFrame(network_alerts), use_container_width=True)
else:
    st.info("No network alerts found")

st.subheader("🛡️ Module 2 — Anti-Forensics Alerts")
if antiforensics_alerts:
    st.dataframe(pd.DataFrame(antiforensics_alerts), use_container_width=True)
else:
    st.info("No anti-forensics alerts found")

st.subheader("🗂️ Module 3 — Artifact Recovery Alerts")
if artifact_alerts:
    st.dataframe(pd.DataFrame(artifact_alerts), use_container_width=True)
else:
    st.info("No artifact alerts found")

st.divider()
st.caption("ShadowTrace | Cybersecurity Portfolio Project | Akhilandeswari Boggarapu")