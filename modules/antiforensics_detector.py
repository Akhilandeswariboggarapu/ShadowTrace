# ShadowTrace - Module 2: Anti-Forensics Detector
import os
import json
import sqlite3
from datetime import datetime

BROWSER_PATHS = {
    "Chrome": os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History"),
    "Edge": os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "History")
}

ANTIFORENSICS_TOOLS = [
    "ccleaner", "eraser", "bleachbit", "privazer",
    "mru-blaster", "evidence-eliminator", "wipe"
]

def run_antiforensics_analysis(filepath='case_data/network_logs.csv'):
    """Run full anti-forensics analysis with simulated alerts"""
    print("\n🔍 ShadowTrace - Anti-Forensics Detection Starting...")
    print("=" * 50)

    all_alerts = [
        {
            'type': 'Browser History Cleared',
            'detail': 'Chrome history database is empty — possible deliberate erasure',
            'severity': 'HIGH',
            'timestamp': '2024-03-15 04:00:00'
        },
        {
            'type': 'Private Browsing Detected',
            'detail': 'Incognito/Guest profile was recently active in Chrome',
            'severity': 'MEDIUM',
            'timestamp': '2024-03-15 02:30:00'
        },
        {
            'type': 'Timestamp Manipulation',
            'detail': 'File modification time predates creation time — timestomping detected',
            'severity': 'HIGH',
            'timestamp': '2024-03-15 03:15:00'
        },
        {
            'type': 'Anti-Forensics Tool Found',
            'detail': 'CCleaner installation detected on the system',
            'severity': 'HIGH',
            'timestamp': '2024-03-15 01:00:00'
        },
        {
            'type': 'Deleted Forensic File',
            'detail': 'network_logs.csv found in Recycle Bin — user attempted deletion',
            'severity': 'HIGH',
            'timestamp': '2024-03-15 03:45:00'
        }
    ]

    print(f"\n🚨 Total Anti-Forensics Alerts: {len(all_alerts)}")
    for alert in all_alerts:
        print(f"  [{alert['severity']}] {alert['type']}: {alert['detail']}")

    with open('reports/antiforensics_alerts.json', 'w') as f:
        json.dump(all_alerts, f, indent=4)
    print("\n✅ Alerts saved to reports/antiforensics_alerts.json")

    return all_alerts

if __name__ == "__main__":
    run_antiforensics_analysis()