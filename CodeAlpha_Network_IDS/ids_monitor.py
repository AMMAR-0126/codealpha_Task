#!/usr/bin/env python3
"""
IDS Alert Monitor
Snort ke alerts real-time mein dikhata hai
"""

import time
import os
from datetime import datetime

LOG_FILE = "/var/log/snort/alert_fast.txt"

def get_icon(line):
    if "ICMP"     in line: return "🟡"
    if "Port Scan" in line: return "🔴"
    if "SSH"      in line: return "🟠"
    if "HTTP"     in line: return "🔵"
    return "⚪"

def monitor():
    print("=" * 55)
    print("   🛡️  IDS Alert Monitor — Snort")
    print("=" * 55)
    print(f"   Log : {LOG_FILE}")
    print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)
    print("   Alerts ka wait kar raha hai...\n")

    stats = {"total":0, "icmp":0, "scan":0, "ssh":0, "http":0}

    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if not line:
                    continue

                stats["total"] += 1
                if "ICMP"      in line: stats["icmp"] += 1
                if "Port Scan" in line: stats["scan"] += 1
                if "SSH"       in line: stats["ssh"]  += 1
                if "HTTP"      in line: stats["http"] += 1

                icon = get_icon(line)

                print(f"\n{'═' * 55}")
                print(f"  {icon} ALERT #{stats['total']} | {datetime.now().strftime('%H:%M:%S')}")
                print(f"{'═' * 55}")
                print(f"  📋 {line}")
                print(f"\n  📊 Total:{stats['total']} | ICMP:{stats['icmp']} | Scan:{stats['scan']} | SSH:{stats['ssh']} | HTTP:{stats['http']}")
            else:
                time.sleep(0.5)

if __name__ == "__main__":
    if not os.path.exists(LOG_FILE):
        print(f"❌ Log file nahi mili: {LOG_FILE}")
        print("   Pehle Snort chalao!")
    else:
        try:
            monitor()
        except KeyboardInterrupt:
            print("\n\n[✓] Monitor band hua!")

