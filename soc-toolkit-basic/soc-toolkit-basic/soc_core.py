import re
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Dict, Any
from dateutil import parser as dt_parser  # not heavily used but kept for extension
import pandas as pd


# ---------- Data models ----------

@dataclass
class Event:
    timestamp: datetime
    src_ip: str
    log_type: str          # auth / web / firewall / other
    raw: str
    extra: Dict[str, Any]


@dataclass
class Alert:
    id: str
    timestamp: datetime
    src_ip: str
    alert_type: str        # brute_force / sql_injection / port_scan / priv_esc
    severity: str          # Low / Medium / High
    description: str
    mitre_id: str
    mitre_name: str
    evidence: Dict[str, Any]
    ti: Dict[str, Any]     # threat intelligence data (simulated here)


# ---------- Helpers ----------

MITRE_MAP = {
    "brute_force": ("T1110", "Brute Force"),
    "sql_injection": ("T1190", "Exploit Public-Facing Application (SQLi)"),
    "port_scan": ("TA0043", "Reconnaissance / Network Service Scanning"),
    "priv_esc": ("T1068", "Exploitation for Privilege Escalation"),
}


def _parse_syslog_datetime(prefix: str) -> datetime:
    # prefix example: "Jan 10 10:01:01"
    # we assume current year
    year = datetime.now().year
    return datetime.strptime(f"{year} {prefix}", "%Y %b %d %H:%M:%S")


# ---------- Log parsers ----------

def parse_auth_log(path: str) -> List[Event]:
    events: List[Event] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Example: Jan 10 10:01:01 host sshd[111]: Failed password for root from 192.168.1.10 port 54321 ssh2
            m = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(.*)$", line)
            if not m:
                continue
            ts_prefix = m.group(1)
            rest = m.group(2)
            ts = _parse_syslog_datetime(ts_prefix)

            src_ip = ""
            event_type = "other"
            if "Failed password" in line:
                event_type = "auth_failed"
                ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    src_ip = ip_match.group(1)
            elif "Accepted password" in line:
                event_type = "auth_success"
                ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    src_ip = ip_match.group(1)
            elif "sudo:" in line:
                event_type = "sudo"
                # here src_ip may be empty (local user)
            events.append(
                Event(
                    timestamp=ts,
                    src_ip=src_ip or "0.0.0.0",
                    log_type="auth",
                    raw=line,
                    extra={"event_type": event_type},
                )
            )
    return events


def parse_web_log(path: str) -> List[Event]:
    events: List[Event] = []
    # Nginx/Apache common log pattern (simplified)
    pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<time>.+?)\]\s+"(?P<req>.+?)"\s+(?P<status>\d+)\s+(?P<size>\d+)'
    )
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = pattern.match(line)
            if not m:
                continue
            ip = m.group("ip")
            time_str = m.group("time").split(" ")[0]  # ignore timezone
            ts = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S")
            req = m.group("req")
            status = int(m.group("status"))
            events.append(
                Event(
                    timestamp=ts,
                    src_ip=ip,
                    log_type="web",
                    raw=line,
                    extra={
                        "request": req,
                        "status": status,
                    },
                )
            )
    return events


def parse_firewall_log(path: str) -> List[Event]:
    events: List[Event] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Example: Jan 10 11:00:05 fw kernel: UFW BLOCK IN 203.0.113.10 -> 192.168.1.100 port 22
            m = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(.*)$", line)
            if not m:
                continue
            ts_prefix = m.group(1)
            ts = _parse_syslog_datetime(ts_prefix)
            src_ip = "0.0.0.0"
            ip_match = re.search(r"UFW .*? (\d+\.\d+\.\d+\.\d+)\s*->", line)
            if ip_match:
                src_ip = ip_match.group(1)
            events.append(
                Event(
                    timestamp=ts,
                    src_ip=src_ip,
                    log_type="firewall",
                    raw=line,
                    extra={},
                )
            )
    return events


def load_all_events(data_dir: str = "data") -> List[Event]:
    events: List[Event] = []
    for fname in os.listdir(data_dir):
        path = os.path.join(data_dir, fname)
        if not os.path.isfile(path):
            continue
        if "auth" in fname:
            events.extend(parse_auth_log(path))
        elif "web" in fname:
            events.extend(parse_web_log(path))
        elif "firewall" in fname:
            events.extend(parse_firewall_log(path))
        # you can add more parsers here
    # sort by time
    events.sort(key=lambda e: e.timestamp)
    return events


# ---------- Detection rules ----------

def detect_bruteforce(events: List[Event],
                      window: timedelta = timedelta(minutes=5),
                      threshold: int = 5) -> List[Alert]:
    alerts: List[Alert] = []
    # group auth_failed by src_ip
    failed_by_ip: Dict[str, List[Event]] = {}
    for e in events:
        if e.log_type == "auth" and e.extra.get("event_type") == "auth_failed" and e.src_ip != "0.0.0.0":
            failed_by_ip.setdefault(e.src_ip, []).append(e)

    for ip, evts in failed_by_ip.items():
        # sliding window logic
        start = 0
        for i in range(len(evts)):
            while evts[i].timestamp - evts[start].timestamp > window:
                start += 1
            count = i - start + 1
            if count >= threshold:
                mitre_id, mitre_name = MITRE_MAP["brute_force"]
                alerts.append(
                    Alert(
                        id=f"BF-{ip}-{evts[i].timestamp.timestamp()}",
                        timestamp=evts[i].timestamp,
                        src_ip=ip,
                        alert_type="brute_force",
                        severity="High",
                        description=f"Detected {count} failed logins from {ip} within {window.total_seconds()/60:.0f} minutes",
                        mitre_id=mitre_id,
                        mitre_name=mitre_name,
                        evidence={
                            "count": count,
                            "first_seen": evts[start].timestamp.isoformat(),
                            "last_seen": evts[i].timestamp.isoformat(),
                        },
                        ti=simulate_threat_intel(ip),
                    )
                )
                break  # one alert per IP for now
    return alerts


def detect_sql_injection(events: List[Event]) -> List[Alert]:
    alerts: List[Alert] = []
    sqli_patterns = [
        r"(\bOR\b\s+1=1)",
        r"UNION\s+SELECT",
        r"'--",
        r"%27%20OR%201=1",
    ]
    compiled = [re.compile(p, re.IGNORECASE) for p in sqli_patterns]

    for e in events:
        if e.log_type != "web":
            continue
        req = e.extra.get("request", "")
        if any(p.search(req) for p in compiled):
            mitre_id, mitre_name = MITRE_MAP["sql_injection"]
            alerts.append(
                Alert(
                    id=f"SQLI-{e.src_ip}-{e.timestamp.timestamp()}",
                    timestamp=e.timestamp,
                    src_ip=e.src_ip,
                    alert_type="sql_injection",
                    severity="High",
                    description=f"Possible SQL Injection from {e.src_ip} in request: {req}",
                    mitre_id=mitre_id,
                    mitre_name=mitre_name,
                    evidence={
                        "request": req,
                        "status": e.extra.get("status"),
                    },
                    ti=simulate_threat_intel(e.src_ip),
                )
            )
    return alerts


def detect_port_scan(events: List[Event],
                     window: timedelta = timedelta(minutes=1),
                     threshold: int = 5) -> List[Alert]:
    alerts: List[Alert] = []
    by_ip: Dict[str, List[Event]] = {}
    for e in events:
        if e.log_type == "firewall":
            by_ip.setdefault(e.src_ip, []).append(e)

    for ip, evts in by_ip.items():
        evts.sort(key=lambda x: x.timestamp)
        start = 0
        for i in range(len(evts)):
            while evts[i].timestamp - evts[start].timestamp > window:
                start += 1
            count = i - start + 1
            if count >= threshold:
                mitre_id, mitre_name = MITRE_MAP["port_scan"]
                alerts.append(
                    Alert(
                        id=f"PS-{ip}-{evts[i].timestamp.timestamp()}",
                        timestamp=evts[i].timestamp,
                        src_ip=ip,
                        alert_type="port_scan",
                        severity="Medium",
                        description=f"Potential port scan from {ip}: {count} firewall hits within {window.total_seconds()} seconds",
                        mitre_id=mitre_id,
                        mitre_name=mitre_name,
                        evidence={
                            "count": count,
                            "sample_raw": evts[start].raw,
                        },
                        ti=simulate_threat_intel(ip),
                    )
                )
                break
    return alerts


def detect_priv_esc(events: List[Event]) -> List[Alert]:
    alerts: List[Alert] = []
    # very simple: if sudo incorrect attempts followed by sudo success near in time
    sudo_events = [e for e in events if e.log_type == "auth" and e.extra.get("event_type") == "sudo"]
    if len(sudo_events) >= 2:
        mitre_id, mitre_name = MITRE_MAP["priv_esc"]
        last = sudo_events[-1]
        alerts.append(
            Alert(
                id=f"PE-{last.src_ip}-{last.timestamp.timestamp()}",
                timestamp=last.timestamp,
                src_ip=last.src_ip,
                alert_type="priv_esc",
                severity="Medium",
                description="Suspicious sudo behaviour detected (multiple incorrect then success).",
                mitre_id=mitre_id,
                mitre_name=mitre_name,
                evidence={"raw": [e.raw for e in sudo_events[-2:]]},
                ti=simulate_threat_intel(last.src_ip or "127.0.0.1"),
            )
        )
    return alerts


# ---------- Threat intel (simulated) ----------

def simulate_threat_intel(ip: str) -> Dict[str, Any]:
    # In a real project, you would call AbuseIPDB, Shodan, VirusTotal etc.
    # Here we just simulate based on IP ranges so the UI has something to show.
    ti = {
        "ip": ip,
        "reputation_score": 10,
        "reports": 0,
        "is_malicious": False,
        "source": "simulated",
    }
    # pretend that public IP ranges are worse
    if ip.startswith("203.") or ip.startswith("198.") or ip.startswith("185."):
        ti["reputation_score"] = 85
        ti["reports"] = 12
        ti["is_malicious"] = True
    return ti


# ---------- High-level pipeline ----------

def generate_alerts(events: List[Event]) -> List[Alert]:
    alerts: List[Alert] = []
    alerts.extend(detect_bruteforce(events))
    alerts.extend(detect_sql_injection(events))
    alerts.extend(detect_port_scan(events))
    alerts.extend(detect_priv_esc(events))

    # deduplicate by id
    uniq = {}
    for a in alerts:
        uniq[a.id] = a
    alerts = list(uniq.values())
    alerts.sort(key=lambda a: a.timestamp)
    return alerts


def alerts_to_dataframe(alerts: List[Alert]) -> pd.DataFrame:
    rows = []
    for a in alerts:
        rows.append(
            {
                "id": a.id,
                "time": a.timestamp,
                "src_ip": a.src_ip,
                "type": a.alert_type,
                "severity": a.severity,
                "description": a.description,
                "mitre_id": a.mitre_id,
                "mitre_name": a.mitre_name,
                "ti_score": a.ti.get("reputation_score", 0),
                "ti_malicious": a.ti.get("is_malicious", False),
            }
        )
    if not rows:
        return pd.DataFrame(columns=["id", "time", "src_ip", "type", "severity"])
    return pd.DataFrame(rows)
