# ShadowTrace - Module 3: Artifact Recovery
# Recovers browser history artifacts from SQLite databases

import os
import sqlite3
import json
from datetime import datetime, timedelta

def convert_chrome_time(chrome_time):
    """Convert Chrome timestamp to readable format"""
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Unknown"

def recover_chrome_history():
    """Recover browsing history from Chrome's SQLite database"""
    print("\n🔍 Recovering Chrome History...")
    alerts = []

    chrome_path = os.path.join(
        os.environ.get("USERPROFILE", ""),
        "AppData", "Local", "Google", "Chrome",
        "User Data", "Default", "History"
    )

    if not os.path.exists(chrome_path):
        print("  ⚠️  Chrome history database not found (may have been deleted)")
        alerts.append({
            'type': 'Missing Browser Database',
            'detail': 'Chrome history file does not exist — possible deletion',
            'severity': 'HIGH',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        return alerts

    try:
        # Copy to temp to avoid lock issues
        import shutil
        temp_path = "case_data/chrome_history_temp.db"
        shutil.copy2(chrome_path, temp_path)

        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT 50
        """)

        rows = cursor.fetchall()
        conn.close()
        os.remove(temp_path)

        print(f"  ✅ Recovered {len(rows)} Chrome history entries")

        recovered = []
        for row in rows:
            url, title, visit_count, last_visit_time = row
            readable_time = convert_chrome_time(last_visit_time)
            recovered.append({
                'browser': 'Chrome',
                'url': url,
                'title': title or 'No Title',
                'visit_count': visit_count,
                'last_visited': readable_time
            })

        # Flag suspicious URLs
        suspicious_keywords = ['torproject.org', 'nordvpn.com', 'hidemyass.com', 
                       'protonvpn.com', 'anonymizer.com', 'darkweb', 
                       'pastebin.com', 'tor2web.org']
        for entry in recovered:
            for keyword in suspicious_keywords:
                if keyword in entry['url'].lower():
                    alerts.append({
                        'type': 'Suspicious Browser History',
                        'detail': f"Visited: {entry['url']}",
                        'severity': 'HIGH',
                        'timestamp': entry['last_visited']
                    })

        # Save recovered history
        with open('reports/recovered_history.json', 'w') as f:
            json.dump(recovered, f, indent=4)
        print("  ✅ Saved to reports/recovered_history.json")

    except Exception as e:
        print(f"  ❌ Error reading Chrome history: {e}")

    return alerts


def recover_simulated_history():
    """Recover history from simulated evidence database"""
    print("\n🔍 Recovering Simulated Browser Artifacts...")
    alerts = []

    sim_path = "case_data/browser_history.db"

    if not os.path.exists(sim_path):
        # Create simulated database for demo
        conn = sqlite3.connect(sim_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time TEXT
            )
        """)
        simulated_entries = [
            ("https://www.torproject.org/download", "Tor Browser Download", 5, "2024-03-15 02:10:00"),
            ("https://nordvpn.com/", "NordVPN - Best VPN Service", 3, "2024-03-15 01:45:00"),
            ("https://protonvpn.com/", "ProtonVPN", 2, "2024-03-14 23:30:00"),
            ("https://www.reddit.com/r/privacy", "Privacy Reddit", 8, "2024-03-14 22:00:00"),
            ("https://pastebin.com/xK92mP1", "Pastebin - Unknown", 1, "2024-03-15 03:00:00"),
        ]
        cursor.executemany("INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?,?,?,?)",
                           simulated_entries)
        conn.commit()
        conn.close()
        print("  ✅ Simulated browser database created")

    conn = sqlite3.connect(sim_path)
    cursor = conn.cursor()
    cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
    rows = cursor.fetchall()
    conn.close()

    print(f"  ✅ Recovered {len(rows)} simulated history entries")

    suspicious_keywords = ['tor', 'vpn', 'proxy', 'pastebin', 'anonymous']
    for row in rows:
        url, title, visit_count, last_visit = row
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                alerts.append({
                    'type': 'Recovered Suspicious URL',
                    'detail': f"Visited {visit_count}x: {url}",
                    'severity': 'HIGH',
                    'timestamp': last_visit
                })

    return alerts


def run_artifact_recovery():
    """Run full artifact recovery analysis"""
    print("\n🔍 ShadowTrace - Artifact Recovery Starting...")
    print("=" * 50)

    all_alerts = []
    all_alerts += recover_chrome_history()
    all_alerts += recover_simulated_history()

    print(f"\n🚨 Total Artifact Alerts: {len(all_alerts)}")
    for alert in all_alerts:
        print(f"  [{alert['severity']}] {alert['type']}: {alert['detail']}")

    with open('reports/artifact_alerts.json', 'w') as f:
        json.dump(all_alerts, f, indent=4)
    print("\n✅ Alerts saved to reports/artifact_alerts.json")

    return all_alerts


if __name__ == "__main__":
    run_artifact_recovery()