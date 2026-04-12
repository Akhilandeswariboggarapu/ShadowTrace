# ShadowTrace - Module 1: Network Analyzer
# Investigates network logs for unauthorized web activity

import pandas as pd
from datetime import datetime
import json

# Known suspicious domains and VPN/TOR indicators
SUSPICIOUS_DOMAINS = [
    "torproject.org", "tor2web.org", "protonvpn.com",
    "nordvpn.com", "hidemyass.com", "anonymizer.com"
]

SUSPICIOUS_PORTS = [9050, 9150, 1194, 1723]  # TOR and VPN ports

def load_logs(filepath):
    """Load network logs from a CSV file"""
    try:
        df = pd.read_csv(filepath)
        print(f"✅ Loaded {len(df)} network log entries")
        return df
    except Exception as e:
        print(f"❌ Error loading logs: {e}")
        return None

def detect_suspicious_domains(df):
    """Flag connections to suspicious domains"""
    alerts = []
    for _, row in df.iterrows():
        domain = str(row.get('domain', '')).lower()
        for sus_domain in SUSPICIOUS_DOMAINS:
            if sus_domain in domain:
                alerts.append({
                    'type': 'Suspicious Domain',
                    'detail': f"Connection to {domain}",
                    'timestamp': row.get('timestamp', 'Unknown'),
                    'severity': 'HIGH'
                })
    return alerts

def detect_suspicious_ports(df):
    """Flag connections on known VPN/TOR ports"""
    alerts = []
    for _, row in df.iterrows():
        port = row.get('port', 0)
        if port in SUSPICIOUS_PORTS:
            alerts.append({
                'type': 'Suspicious Port',
                'detail': f"Traffic on port {port} (VPN/TOR indicator)",
                'timestamp': row.get('timestamp', 'Unknown'),
                'severity': 'HIGH'
            })
    return alerts

def detect_after_hours(df, start_hour=9, end_hour=18):
    """Flag network activity outside business hours"""
    alerts = []
    for _, row in df.iterrows():
        try:
            ts = datetime.strptime(str(row['timestamp']), '%Y-%m-%d %H:%M:%S')
            if ts.hour < start_hour or ts.hour >= end_hour:
                alerts.append({
                    'type': 'After Hours Activity',
                    'detail': f"Network access at {ts.strftime('%H:%M')}",
                    'timestamp': row.get('timestamp', 'Unknown'),
                    'severity': 'MEDIUM'
                })
        except:
            pass
    return alerts

def detect_large_transfers(df, threshold_mb=50):
    """Flag unusually large data transfers"""
    alerts = []
    for _, row in df.iterrows():
        bytes_sent = row.get('bytes_sent', 0)
        mb_sent = bytes_sent / (1024 * 1024)
        if mb_sent > threshold_mb:
            alerts.append({
                'type': 'Large Data Transfer',
                'detail': f"{mb_sent:.2f} MB sent to {row.get('domain', 'Unknown')}",
                'timestamp': row.get('timestamp', 'Unknown'),
                'severity': 'HIGH'
            })
    return alerts

def run_analysis(filepath):
    """Run full network analysis and return all alerts"""
    print("\n🔍 ShadowTrace - Network Analysis Starting...")
    print("=" * 50)

    df = load_logs(filepath)
    if df is None:
        return []

    all_alerts = []
    all_alerts += detect_suspicious_domains(df)
    all_alerts += detect_suspicious_ports(df)
    all_alerts += detect_after_hours(df)
    all_alerts += detect_large_transfers(df)

    print(f"\n🚨 Total Alerts Found: {len(all_alerts)}")
    for alert in all_alerts:
        print(f"  [{alert['severity']}] {alert['type']}: {alert['detail']}")

    # Save alerts to JSON
    with open('reports/network_alerts.json', 'w') as f:
        json.dump(all_alerts, f, indent=4)
    print("\n✅ Alerts saved to reports/network_alerts.json")

    return all_alerts

if __name__ == "__main__":
    run_analysis('case_data/network_logs.csv')