# ShadowTrace - Module 2: Anti-Forensics Detector
# Detects when someone tried to cover their tracks

import os
import json
import sqlite3
from datetime import datetime

# Common browser history database paths
BROWSER_PATHS = {
    "Chrome": os.path.expanduser("~") + r"\AppData\Local\Google\Chrome\User Data\Default\History",
    "Firefox": os.path.expanduser("~") + r"\AppData\Roaming\Mozilla\Firefox\Profiles",
    "Edge": os.path.expanduser("~") + r"\AppData\Local\Microsoft\Edge\User Data\Default\History"
}

# Known anti-forensics tools
ANTIFORENSICS_TOOLS = [
    "ccleaner", "eraser", "bleachbit", "privazer",
    "mru-blaster", "evidence-eliminator", "wipe"
]

def check_browser_history_cleared(browser="Chrome"):
    """Detect if browser history was recently cleared"""
    alerts = []
    path = BROWSER_PATHS.get(browser)

    if not path or not os.path.exists(path):
        alerts.append({
            'type': 'Browser History Missing',
            'detail': f"{browser} history database not found — may have been deleted",
            'severity': 'HIGH',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        return alerts

    # Check if history file is suspiciously small (cleared)
    file_size = os.path.getsize(path)
    if file_size < 50000:  # Less than 50KB means likely cleared
        alerts.append({
            'type': 'Browser History Cleared',
            'detail': f"{browser} history is unusually small ({file_size} bytes) — likely wiped",
            'severity': 'HIGH',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

    return alerts

def check_private_browsing_artifacts(browser="Chrome"):
    """Detect signs of private/incognito browsing"""
    alerts = []

    # Check for crash recovery files left by incognito sessions
    local_state_path = os.path.expanduser("~") + \
        r"\AppData\Local\Google\Chrome\User Data\Local State"

    if os.path.exists(local_state_path):
        try:
            with open(local_state_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Check if incognito was used recently
                if data.get('profile', {}).get('last_used_profile', '') == 'Guest Profile':
                    alerts.append({
                        'type': 'Incognito/Private Browsing Detected',
                        'detail': "Evidence of Guest/Incognito profile usage found",
                        'severity': 'MEDIUM',
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
        except:
            pass

    return alerts

def check_timestamp_manipulation(filepath):
    """Detect if file timestamps were tampered with"""
    alerts = []

    if not os.path.exists(filepath):
        return alerts

    try:
        stat = os.stat(filepath)
        created = datetime.fromtimestamp(stat.st_ctime)
        modified = datetime.fromtimestamp(stat.st_mtime)
        accessed = datetime.fromtimestamp(stat.st_atime)

        # If modified time is BEFORE created time — tampering detected
        if modified < created:
            alerts.append({
                'type': 'Timestamp Manipulation',
                'detail': f"File modified ({modified}) BEFORE it was created ({created}) — timestamps tampered",
                'severity': 'HIGH',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })

        # If all timestamps are identical — suspicious (automated wiping tools do this)
        if created == modified == accessed:
            alerts.append({
                'type': 'Suspicious Uniform Timestamps',
                'detail': "All timestamps are identical — possible automated timestamp reset",
                'severity': 'MEDIUM',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })

    except Exception as e:
        print(f"Error checking timestamps: {e}")

    return alerts

def check_recently_deleted_files():
    """Check recycle bin for recently deleted evidence files"""
    alerts = []
    recycle_path = "C:\\$Recycle.Bin"

    try:
        if os.path.exists(recycle_path):
            for root, dirs, files in os.walk(recycle_path):
                for file in files:
                    # Flag deleted log or database files
                    if any(file.endswith(ext) for ext in ['.log', '.db', '.sqlite', '.csv', '.pcap']):
                        alerts.append({
                            'type': 'Deleted Evidence File',
                            'detail': f"Forensic file found in Recycle Bin: {file}",
                            'severity': 'HIGH',
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        })
    except PermissionError:
        alerts.append({
            'type': 'Recycle Bin Access Denied',
            'detail': "Could not access Recycle Bin — may indicate permission tampering",
            'severity': 'MEDIUM',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

    return alerts

def check_antiforensics_tools_installed():
    """Check for known evidence-wiping tools in common install locations"""
    alerts = []
    search_paths = [
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        os.path.expanduser("~") + "\\AppData\\Local"
    ]

    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue
        try:
            for item in os.listdir(search_path):
                for tool in ANTIFORENSICS_TOOLS:
                    if tool.lower() in item.lower():
                        alerts.append({
                            'type': 'Anti-Forensics Tool Detected',
                            'detail': f"Evidence wiping tool found: {item} in {search_path}",
                            'severity': 'HIGH',
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        })
        except PermissionError:
            pass

    return alerts

def run_antiforensics_analysis(filepath="case_data/network_logs.csv"):
    """Run all anti-forensics checks and return alerts"""
    print("\n🕵️  ShadowTrace - Anti-Forensics Detection Starting...")
    print("=" * 50)

    all_alerts = []

    print("🔍 Checking browser history...")
    all_alerts += check_browser_history_cleared("Chrome")
    all_alerts += check_browser_history_cleared("Edge")

    print("🔍 Checking for private browsing artifacts...")
    all_alerts += check_private_browsing_artifacts()

    print("🔍 Checking for timestamp manipulation...")
    all_alerts += check_timestamp_manipulation(filepath)

    print("🔍 Checking recycle bin for deleted evidence...")
    all_alerts += check_recently_deleted_files()

    print("🔍 Checking for anti-forensics tools...")
    all_alerts += check_antiforensics_tools_installed()

    print(f"\n🚨 Anti-Forensics Alerts Found: {len(all_alerts)}")
    for alert in all_alerts:
        print(f"  [{alert['severity']}] {alert['type']}: {alert['detail']}")

    # Save to JSON
    with open('reports/antiforensics_alerts.json', 'w') as f:
        json.dump(all_alerts, f, indent=4)
    print("\n✅ Alerts saved to reports/antiforensics_alerts.json")

    return all_alerts

if __name__ == "__main__":
    run_antiforensics_analysis()