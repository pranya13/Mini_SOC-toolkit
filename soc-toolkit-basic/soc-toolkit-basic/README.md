# Cyber SOC Analyst Toolkit (Basic Version)

This is a beginner-friendly **mini SOC (Security Operations Center) toolkit** project.

## What it does

- Reads sample log files from the `data/` folder:
  - `sample_auth.log` (Linux auth / SSH / sudo logs)
  - `sample_web.log` (web server access logs)
  - `sample_firewall.log` (firewall logs)
- Parses logs into structured events (timestamp, IP, type).
- Detects:
  - Brute-force login attempts (many failed SSH logins from same IP).
  - SQL Injection (SQLi) patterns in web requests.
  - Port scanning behaviour from firewall logs.
  - Suspicious sudo behaviour (simple privilege escalation hint).
- Generates alerts and maps them to **MITRE ATT&CK** techniques.
- Adds **simulated Threat Intelligence** (fake reputation score) for IPs.
- Displays everything in a **Streamlit dashboard** with multiple pages.

## Tech stack

- **Python**
- **Streamlit** for the UI
- **pandas** for data handling
- **regex** for log parsing
- Basic datetime & sliding window logic for detections

## How to run

1. Create and activate a virtual environment (recommended).
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the Streamlit app:

   ```bash
   streamlit run app.py
   ```

4. Open the URL shown in your terminal (usually http://localhost:8501).

## Project structure

```text
soc-toolkit-basic/
├─ app.py                # Streamlit UI
├─ soc_core.py           # Core logic (parsing, detection, TI simulation, MITRE mapping)
├─ requirements.txt
├─ README.md
└─ data/
   ├─ sample_auth.log
   ├─ sample_web.log
   └─ sample_firewall.log
```

## How to extend this project

- Replace or add real logs into the `data/` folder (auth, web, firewall).
- Implement real Threat Intelligence calls (AbuseIPDB, Shodan, VirusTotal).
- Add more detection rules (DNS tunnelling, malware URLs, etc.).
- Store alerts in a database (SQLite) and add historical views.
- Implement real firewall actions using `ufw` (Linux) or PowerShell (Windows).

This project is ideal for learning **log analysis, threat detection, and SOC/blue-team concepts**.
