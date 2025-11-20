import streamlit as st
import pandas as pd
from soc_core import load_all_events, generate_alerts, alerts_to_dataframe


st.set_page_config(
    page_title="SOC Analyst Toolkit (Basic)",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_data
def load_data():
    events = load_all_events("data")
    alerts = generate_alerts(events)
    df_alerts = alerts_to_dataframe(alerts)
    return events, alerts, df_alerts


def main():
    st.title("🔐 Cyber SOC Analyst Toolkit (Basic Version)")
    st.caption("Mini SIEM-style project: detects brute force, SQL injection, port scanning & suspicious sudo from logs.")

    events, alerts, df_alerts = load_data()

    # ---- Sidebar navigation ----
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Go to",
        ["Dashboard", "Alerts Explorer", "IP Intelligence", "Raw Logs & Help"],
    )

    st.sidebar.markdown("---")
    st.sidebar.subheader("Filters")

    severity_filter = st.sidebar.multiselect(
        "Severity", options=["High", "Medium", "Low"], default=["High", "Medium", "Low"]
    )

    type_filter = st.sidebar.multiselect(
        "Alert type",
        options=["brute_force", "sql_injection", "port_scan", "priv_esc"],
        default=["brute_force", "sql_injection", "port_scan", "priv_esc"],
    )

    if not df_alerts.empty:
        df_filtered = df_alerts[
            df_alerts["severity"].isin(severity_filter)
            & df_alerts["type"].isin(type_filter)
        ]
    else:
        df_filtered = df_alerts

    if page == "Dashboard":
        show_dashboard(df_filtered)
    elif page == "Alerts Explorer":
        show_alerts_explorer(df_filtered)
    elif page == "IP Intelligence":
        show_ip_intel(df_filtered)
    else:
        show_raw_logs_help(events)


def show_dashboard(df: pd.DataFrame):
    st.subheader("📊 SOC Overview")

    if df.empty:
        st.info("No alerts generated from current logs. Add more log files in the data/ folder to see detections.")
        return

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Alerts", len(df))
    col2.metric("High Severity", int((df["severity"] == "High").sum()))
    col3.metric("Unique Source IPs", df["src_ip"].nunique())
    col4.metric("Malicious IPs (Simulated TI)", int(df["ti_malicious"].sum()))

    st.markdown("### Alerts by Type")
    type_counts = df["type"].value_counts()
    st.bar_chart(type_counts)

    st.markdown("### Alerts by Severity")
    sev_counts = df["severity"].value_counts()
    st.bar_chart(sev_counts)

    st.markdown("### Recent Alerts")
    st.dataframe(
        df.sort_values("time", ascending=False).head(10),
        use_container_width=True,
    )


def show_alerts_explorer(df: pd.DataFrame):
    st.subheader("🔍 Alerts Explorer")

    if df.empty:
        st.info("No alerts available.")
        return

    selected_id = st.selectbox("Select an alert ID", df["id"].tolist())

    alert_row = df[df["id"] == selected_id].iloc[0]
    st.markdown("#### Alert Summary")
    st.write(f"**ID:** {alert_row['id']}")
    st.write(f"**Time:** {alert_row['time']}")
    st.write(f"**Source IP:** `{alert_row['src_ip']}`")
    st.write(f"**Type:** `{alert_row['type']}`")
    st.write(f"**Severity:** `{alert_row['severity']}`")
    st.write(f"**Description:** {alert_row['description']}")
    st.write(f"**MITRE:** {alert_row['mitre_id']} – {alert_row['mitre_name']}")

    st.markdown("#### Threat Intelligence (Simulated)")
    col1, col2 = st.columns(2)
    col1.metric("Reputation Score", alert_row["ti_score"])
    col2.metric("Marked Malicious", "Yes" if alert_row["ti_malicious"] else "No")

    st.markdown("#### Actions")
    if st.button("🚫 Simulate Block IP"):
        st.success(
            f"Simulated blocking IP {alert_row['src_ip']} (in a real deployment this would call firewall commands like ufw or PowerShell)."
        )


def show_ip_intel(df: pd.DataFrame):
    st.subheader("🌍 IP Intelligence View")

    if df.empty:
        st.info("No alerts → no IPs to show.")
        return

    ip_list = sorted(df["src_ip"].unique())
    selected_ip = st.selectbox("Select IP", ip_list)

    ip_df = df[df["src_ip"] == selected_ip]
    st.markdown(f"#### Alerts for `{selected_ip}`")
    st.dataframe(
        ip_df[["time", "type", "severity", "description", "mitre_id"]],
        use_container_width=True,
    )

    st.markdown("#### TI Summary (Simulated)")
    score = ip_df["ti_score"].iloc[0]
    mal = bool(ip_df["ti_malicious"].iloc[0])
    st.metric("Reputation Score", score)
    st.metric("Malicious", "Yes" if mal else "No")

    st.info(
        "In a real deployment, this view could call live Threat Intelligence APIs such as AbuseIPDB, Shodan, or VirusTotal."
    )


def show_raw_logs_help(events):
    st.subheader("📄 Raw Logs & How This Works")

    st.markdown(
        """
This project is a **mini SOC toolkit** built for learning and demonstration:

1. It reads log files from the `data/` folder  
2. Parses them into structured events (timestamp, IP, log type, extra fields)  
3. Applies rule-based detection for:
   - brute-force login attempts  
   - SQL injection (SQLi) in web requests  
   - port scanning behaviour from firewall logs  
   - suspicious sudo behaviour (privilege escalation hint)  
4. Generates alerts, maps them to **MITRE ATT&CK** techniques, and attaches **simulated threat intelligence**.  
5. The Streamlit UI lets you:
   - see a dashboard of alerts  
   - explore each alert in detail  
   - review alerts per IP  
   - simulate response actions like blocking IPs.

🔧 **How to extend it (ideas):**
- Add real Threat Intelligence API calls (AbuseIPDB, Shodan, VirusTotal)  
- Add more log parsers (Windows Event Logs, IDS logs, VPN logs)  
- Store alerts in a database (e.g., SQLite)  
- Implement email notifications for High severity alerts.

To test with your own logs, add files in `data/` with names containing:
- `auth` for authentication logs  
- `web` for web access logs  
- `firewall` for firewall logs  
and reload the app.
"""
    )

    st.markdown("### Preview of Parsed Events (first 50)")
    if not events:
        st.info("No events loaded.")
        return

    rows = []
    for e in events[:50]:
        rows.append(
            {
                "time": e.timestamp,
                "src_ip": e.src_ip,
                "log_type": e.log_type,
                "raw": e.raw[:150],
            }
        )
    df_events = pd.DataFrame(rows)
    st.dataframe(df_events, use_container_width=True)


if __name__ == "__main__":
    main()
