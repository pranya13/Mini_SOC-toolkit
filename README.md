🔐 Mini SOC Toolkit — Log-Based Threat Detection

A beginner-friendly Security Operations Center (SOC) simulation project that performs basic threat detection using parsed Linux, web server, and firewall logs.
This project demonstrates how SOC teams analyze logs, detect attacks, classify threat severity, and respond to incidents.

⭐ Features

✔ Parse logs from:

Linux authentication logs (auth.log)

Web server access logs (Apache / Nginx)

Firewall logs (UFW / iptables-style)

✔ Detect cyber attacks:

Brute-force login attempts

SQL injection (SQLi) in web requests

Port scanning activity

Suspicious sudo behavior (privilege escalation hint)

✔ MITRE ATT&CK Mapping
Each alert links to the correct MITRE technique (e.g., T1110 Brute Force).

✔ Simulated Threat Intelligence
Assigns reputation scores to attacker IPs (can be replaced later with real APIs).

✔ Streamlit Dashboard

Alerts dashboard

Alerts explorer view

IP intelligence page

Simulated “Block IP” action

Log preview & explanation page

🗂 Project Structure
soc-toolkit-basic/
├── app.py               # Streamlit UI
├── soc_core.py          # Parsing + detection + MITRE + TI logic
├── requirements.txt
├── README.md
└── data/
    ├── sample_auth.log
    ├── sample_web.log
    └── sample_firewall.log

🚀 Getting Started
1️⃣ Install dependencies
pip install -r requirements.txt

2️⃣ Launch the dashboard
streamlit run app.py


Open the link shown (usually http://localhost:8501
).

📊 How It Works

Load log files from the data/ folder

Convert raw logs → structured events (IP, timestamp, type)

Run rule-based detectors to find:

multiple failed logins

SQL injection patterns

repeated blocked firewall hits

unusual sudo behavior

Generate alerts with severity, MITRE mapping & threat intel

Display results in the Streamlit UI

🛠 Extend This Project

You can enhance the toolkit by adding:

Real Threat Intelligence APIs

AbuseIPDB

Shodan

VirusTotal

Windows Event Log parsing

Email alerting

SQLite alert database

Automated firewall blocking via UFW / PowerShell

Additional detection rules (DNS tunneling, malware URLs, etc.)

📘 Purpose of This Project

This project is ideal for students and beginners learning:

SOC workflows

Log analysis

Threat detection logic

MITRE ATT&CK

Python for cybersecurity

Building simple security dashboards
