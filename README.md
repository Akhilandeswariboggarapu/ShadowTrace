# ShadowTrace# 🕵️ ShadowTrace
### Forensic Investigation of Unauthorized Web Activity & Anti-Forensics Behavior

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red)
![Status](https://img.shields.io/badge/Status-Complete-green)
![Portfolio](https://img.shields.io/badge/Portfolio-Cybersecurity-darkgreen)

---

## 📌 Project Overview
ShadowTrace is an open-source digital forensics tool designed to investigate 
unauthorized web activity and detect anti-forensics behavior within enterprise 
network environments.

Built as a cybersecurity portfolio project demonstrating real-world DFIR 
(Digital Forensics & Incident Response) skills.

---

## 🚨 Investigation Scenario
An employee is suspected of accessing restricted websites and attempting to 
erase all traces of their activity. ShadowTrace systematically uncovers the 
evidence across 5 investigation modules.

---

## 🔍 Modules

| Module | Description | Output |
|--------|-------------|--------|
| 🌐 Module 1 — Network Analyzer | Detects TOR/VPN usage, suspicious ports, after-hours activity, large transfers | `network_alerts.json` |
| 🛡️ Module 2 — Anti-Forensics Detector | Detects browser clearing, timestomping, wiping tools | `antiforensics_alerts.json` |
| 🗂️ Module 3 — Artifact Recovery | Recovers deleted browser history from SQLite databases | `artifact_alerts.json` |
| 📊 Module 4 — Dashboard | Interactive Streamlit web dashboard with charts | Live Dashboard |
| 📄 Module 5 — Report Generator | Professional PDF forensic case report | `ShadowTrace_Forensic_Report.pdf` |

---

## 📊 Sample Results