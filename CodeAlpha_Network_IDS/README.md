# CodeAlpha Network IDS (Intrusion Detection System)

## 📌 Overview
A **Network Intrusion Detection System (IDS)** built using Python and Snort. Monitors network traffic and generates alerts for suspicious activity. Built as part of the **CodeAlpha Internship** program.

## 🛠️ Tech Stack
- **Language:** Python
- **IDS Engine:** Snort
- **Config:** Lua (snort.lua)

## 📂 Files
| File | Description |
|------|-------------|
| `ids_monitor.py` | Main Python script to run and monitor IDS alerts |
| `snort.lua` | Snort configuration file |
| `local.rules` | Custom Snort detection rules |
| `alert_fast.txt` | Generated alert log file |

## 🚀 How to Run
```bash
# Install Snort
sudo apt-get install snort

# Run IDS monitor
sudo python3 ids_monitor.py
```

## ⚙️ Features
- Real-time network intrusion detection
- Custom rule-based alerting
- Snort integration for deep packet inspection
- Alert logging to `alert_fast.txt`

## ⚠️ Disclaimer
This tool is for **educational purposes only**. Use only on networks you own or have permission to monitor.

## 👨‍💻 Author
**AMMAR-0126** — CodeAlpha Internship Task
