from utils.config import traffic_rate, dos_threshold, ddos_threshold
from alerter.alert import alert
import datetime

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module identifies potential C2 communications and other network anomalies by analyzing network flows. \
             It uses configurable thresholds to detect unusual traffic patterns, such as high traffic volumes, frequent short bursts, \
             and regular communications intervals, which are indicative of C2 activities.",
    "Title": "C2 and Anomaly Detection Module",
    "Date": "23 APR 2024",
    "Category": "Network Security",
    "Description": "This module leverages detailed flow data to monitor and analyze network traffic for signs of command and control (C2) \
                    activities or other anomalies. Utilizing dynamic thresholds from a configuration file, the module is capable of detecting \
                    high traffic volumes, abnormal packet sizes, and suspicious regularity in traffic patterns. Alerts are triggered when \
                    traffic deviates from typical patterns, facilitating timely response and mitigation.",
    "References": [
        "https://www.mitre.org/publications/technical-papers/detecting-cyber-attacks-with-a-context-aware-incident-response",  # Context-Aware Incident Response
        "https://www.nist.gov/cybersecurity",  # National Institute of Standards and Technology on Cybersecurity
        "https://www.sans.org/reading-room/whitepapers/detection/developing-anomaly-detection-system-detect-malicious-connection-34490"  # Developing Anomaly Detection Systems
    ]

}

def detect_dos_ddos( pkt ):
    
    global traffic_rate
    timestamp = datetime.datetime.now()

    traffic_rate[ timestamp ] = traffic_rate.get( timestamp, 0 ) + 1
    total_rate = 0
    cutoff_time = timestamp - datetime.timedelta(seconds=1)
    for ts, rate in traffic_rate.items():
        if ts >= cutoff_time:
            total_rate += rate

    if total_rate > ddos_threshold:
        alert("[*] ALERT !!! DDoS Attack", "", f"Spike in network traffic detected (DDoS). Total rate: {total_rate} pps")
    elif total_rate > dos_threshold:
        alert("[*] ALERT !!! DoS Attack", "", f"Spike in network traffic detected (DoS). Total rate: {total_rate} pps")
