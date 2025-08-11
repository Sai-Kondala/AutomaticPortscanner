import streamlit as st
import nmap
import requests
import pandas as pd
import json
from datetime import datetime
from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import os
import atexit

# --- Core Scanner and Reporting Functions ---

def run_nmap_scan(target_ip):
    """Runs an Nmap scan to find open ports and services."""
    nm = nmap.PortScanner()
    try:
        scan_results = nm.scan(hosts=target_ip, arguments='-sV -T4 --top-ports 1000')
        return scan_results
    except nmap.PortScannerError as e:
        st.error(f"Nmap Error: {e}. Ensure Nmap is installed and you have permissions.")
        return None

def get_cves_for_service(service, version):
    """Queries the CVE-Search API for vulnerabilities."""
    if not service or not version:
        return []
    query = f"{service}/{version}"
    try:
        response = requests.get(f"https://cve.circl.lu/api/search/{query}")
        response.raise_for_status()
        data = response.json().get('data', [])
        return data if data else []
    except (requests.RequestException, json.JSONDecodeError) as e:
        st.warning(f"Could not fetch CVEs for {service} {version}: {e}")
        return []

def generate_html_report(scan_results_df, cve_list, target_ip):
    """Generates an HTML report from the 'template.html' file."""
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('template.html')
    services_html_table = scan_results_df.to_html(index=False, border=0)
    return template.render(
        target_ip=target_ip,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        services_table=services_html_table,
        cves=cve_list
    )

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Vulnerability Scan Report', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(scan_results_df, cve_list, target_ip):
    """Generates a PDF report."""
    pdf = PDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 11)
    pdf.cell(0, 10, f"Target Host: {target_ip}", 0, 1)
    pdf.cell(0, 10, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
    pdf.ln(10)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, "Discovered Services", 0, 1)
    pdf.set_font('Arial', '', 10)
    col_widths = [20, 25, 40, 40, 25]
    header = ['Port', 'State', 'Service', 'Product', 'Version']
    for i, h in enumerate(header):
        pdf.cell(col_widths[i], 7, h, 1, 0, 'C')
    pdf.ln()
    for index, row in scan_results_df.iterrows():
        pdf.cell(col_widths[0], 6, str(row['Port']), 1)
        pdf.cell(col_widths[1], 6, row['State'], 1)
        pdf.cell(col_widths[2], 6, row['Product'], 1)
        pdf.cell(col_widths[3], 6, row['Service'], 1)
        pdf.cell(col_widths[4], 6, row['Version'], 1)
        pdf.ln()
    pdf.ln(10)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, "Vulnerability Details", 0, 1)
    pdf.set_font('Arial', '', 10)
    if not cve_list:
        pdf.multi_cell(0, 10, "No vulnerabilities found.")
    else:
        for cve in cve_list:
            pdf.set_font('Arial', 'B', 10)
            # Use try-except for summary to handle potential encoding issues
            try:
                summary = cve.get('summary', 'No summary available.').encode('latin-1', 'replace').decode('latin-1')
            except:
                summary = "Could not decode summary."
            pdf.multi_cell(0, 5, f"{cve.get('id', 'N/A')} (CVSS: {cve.get('cvss', 'N/A')})", 0, 1)
            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(0, 5, summary)
            pdf.ln(5)
    return bytes(pdf.output(dest='S'))

def send_slack_notification(webhook_url, target_ip, cve_list):
    """Sends a notification to a Slack webhook."""
    if not cve_list:
        return
    message_blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f":warning: Vulnerabilities Detected on {target_ip}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"A recent scan found *{len(cve_list)}* potential vulnerabilities."}},
        {"type": "divider"}
    ]
    for cve in cve_list[:5]:
        message_blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*<{cve.get('references', ['#'])[0]}|{cve.get('id', 'N/A')}>* (CVSS: *{cve.get('cvss', 'N/A')}*)\n{cve.get('summary', 'No summary.')}"
            }
        })
    payload = {"blocks": message_blocks}
    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        st.info("Slack notification sent successfully!")
    except requests.RequestException as e:
        st.error(f"Failed to send Slack notification: {e}")

def perform_scan_and_update_state(target_ip, slack_webhook_url=None):
    """Performs the scan and saves results to session_state."""
    with st.spinner(f"Scanning {target_ip}..."):
        nmap_results = run_nmap_scan(target_ip)
    if not nmap_results or not nmap_results.get('scan'):
        st.error("Scan failed or no hosts found.")
        st.session_state.scan_results_df = pd.DataFrame() # Clear old results
        st.session_state.cve_list = []
        return

    scan_data = []
    for host in nmap_results['scan']:
        if 'tcp' in nmap_results['scan'][host]:
            for port, port_info in nmap_results['scan'][host]['tcp'].items():
                scan_data.append({
                    "Port": port, "State": port_info.get('state', 'unknown'),
                    "Service": port_info.get('name', 'unknown'), "Product": port_info.get('product', ''),
                    "Version": port_info.get('version', ''),
                })
    if not scan_data:
        st.info("No open TCP ports found.")
        st.session_state.scan_results_df = pd.DataFrame()
        st.session_state.cve_list = []
        return
        
    df = pd.DataFrame(scan_data)
    cve_list = []
    with st.spinner("Cross-referencing services with CVE database..."):
        for _, row in df.iterrows():
            if row['State'] == 'open' and row['Product'] and row['Version']:
                cve_search_term = row['Product'].lower()
                cves = get_cves_for_service(cve_search_term, row['Version'])
                if cves: cve_list.extend(cves)
    
    # Save results to session state for the main panel to display
    st.session_state.scan_results_df = df
    st.session_state.cve_list = cve_list
    
    if cve_list and slack_webhook_url:
        send_slack_notification(slack_webhook_url, target_ip, cve_list)

# --- Streamlit UI ---
st.set_page_config(page_title="Advanced Vulnerability Scanner", layout="wide",page_icon="🛡️",)

# Initialize session state
if 'scan_results_df' not in st.session_state:
    st.session_state.scan_results_df = None
if 'cve_list' not in st.session_state:
    st.session_state.cve_list = None
if 'scheduler' not in st.session_state:
    st.session_state.scheduler = BackgroundScheduler()
    st.session_state.scheduler.start()
    st.session_state.job = None

# --- Sidebar for Controls ---
with st.sidebar:
    st.header("Scan Configuration")
    target_ip = st.text_input("Enter Target IP Address", "127.0.0.1")
    slack_webhook_url = st.text_input("Slack Webhook URL (Optional)", type="password")
    
    if st.button("▶️ Run Scan Now", use_container_width=True):
        perform_scan_and_update_state(target_ip, slack_webhook_url)

    st.header("Scheduled Scans")
    enable_scheduling = st.toggle("Enable Scheduled Scanning")
    schedule_interval = st.number_input("Scan Interval (minutes)", min_value=1, value=60)

    if enable_scheduling:
        if st.session_state.job is None or not st.session_state.job.next_run_time:
            st.session_state.job = st.session_state.scheduler.add_job(
                lambda: perform_scan_and_update_state(target_ip, slack_webhook_url),
                trigger=IntervalTrigger(minutes=schedule_interval),
                id='scheduled_scan_job', name='Vulnerability Scan', replace_existing=True
            )
            st.success(f"Scan scheduled to run every {schedule_interval} minutes.")
        next_run = st.session_state.job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if st.session_state.job else "N/A"
        st.info(f"Next scheduled scan: {next_run}")
    else:
        if st.session_state.job:
            st.session_state.job.remove()
            st.session_state.job = None
            st.warning("Scheduled scanning disabled.")
            
    st.header("Download Report")
    if st.session_state.scan_results_df is not None and not st.session_state.scan_results_df.empty:
        html_report = generate_html_report(st.session_state.scan_results_df, st.session_state.cve_list, target_ip)
        st.download_button(
            label="📄 Download HTML Report", data=html_report,
            file_name=f"scan_report_{target_ip}.html", mime="text/html", use_container_width=True
        )
        pdf_report = generate_pdf_report(st.session_state.scan_results_df, st.session_state.cve_list, target_ip)
        st.download_button(
            label="📕 Download PDF Report", data=pdf_report,
            file_name=f"scan_report_{target_ip}.pdf", mime="application/pdf", use_container_width=True
        )

# --- Main Panel for Results ---
st.title("🛡️ Advanced Vulnerability Scanner")
st.markdown("An automated tool for network scanning, vulnerability detection, and reporting.")

if st.session_state.scan_results_df is None:
    st.markdown("### Click 'Run Scan Now' in the sidebar to begin.")
elif st.session_state.scan_results_df.empty:
    st.info("Scan complete. No open TCP ports were found.")
else:
    st.success("Scan complete!")
    st.subheader("Discovered Services")
    st.dataframe(st.session_state.scan_results_df, use_container_width=True)
    
    st.subheader("Vulnerability Analysis")
    cve_list = st.session_state.cve_list
    if not cve_list:
        st.success("No known CVEs found for the discovered services and versions.")
    else:
        st.error(f"Found {len(cve_list)} potential vulnerabilities!")
        with st.expander("Click to see detailed CVE results"):
            for cve in cve_list:
                st.error(f"**{cve.get('id', 'N/A')}** (CVSS Score: {cve.get('cvss', 'N/A')})")
                st.write(cve.get('summary', 'No summary available.'))
                st.markdown("---")

st.markdown("---")
st.markdown("**Disclaimer:** This tool is for educational purposes only. Only scan networks and systems that you own or have explicit, written permission to test. Unauthorized scanning is illegal.")

atexit.register(lambda: st.session_state.scheduler.shutdown() if st.session_state.scheduler.running else None)
