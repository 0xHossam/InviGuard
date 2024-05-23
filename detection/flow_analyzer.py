import collections
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from alerter.alert import alert
from configs.config_loader import load_config

module_info = {

    "Author": "Hossam Ehab",
    "Info": "Identifies potential C2 communications and anomalies by analyzing network flows and detecting unusual traffic patterns.",
    "Title": "C2 and Anomaly Detection Module",
    "Date": "22 APR 2024",
    "Category": "Network Security",
    "Description": "Monitors network traffic for signs of C2 activities and anomalies using dynamic thresholds for high traffic volumes and abnormal patterns.",
    "References": [
        "https://www.mitre.org/publications/technical-papers/detecting-cyber-attacks-with-a-context-aware-incident-response",
        "https://www.nist.gov/cybersecurity",
        "https://www.sans.org/reading-room/whitepapers/detection/developing-anomaly-detection-system-detect-malicious-connection-34490"
    ]

}

# Load configuration
config = load_config()
thresholds = config['thresholds']

# Thresholds from configuration
high_traffic_threshold = thresholds['high_traffic_threshold']
high_packet_count_threshold = thresholds['high_packet_count_threshold']
short_duration_threshold = thresholds['short_duration_threshold']

def manual_round(value):
    return round(value * 100) / 100

# Dictionary to store flow data
flows = collections.defaultdict(lambda: {
    'packet_count': 0,
    'byte_count': 0,
    'start_time': None,
    'end_time': None,
    'timestamps': [],
    'src_ports': set(),
    'dst_ports': set()
})

def analyze_flow(key, flow_data):
    if flow_data['start_time'] and flow_data['end_time']:
        duration = (flow_data['end_time'] - flow_data['start_time']).total_seconds()
        duration = manual_round(duration)
    else:
        duration = 0

    if flow_data['packet_count'] > 0:
        average_packet_size = flow_data['byte_count'] / flow_data['packet_count']
        average_packet_size = manual_round(average_packet_size)
    else:
        average_packet_size = 0

    # Detect anomalies based on thresholds from config
    if flow_data['byte_count'] > high_traffic_threshold and duration < short_duration_threshold:
        alert_detail = f"Flow {key} transferred {flow_data['byte_count']} bytes in {duration} seconds."
        alert("High Traffic Anomaly", key[0], alert_detail)
    elif flow_data['packet_count'] > high_packet_count_threshold and average_packet_size < 150:
        alert_detail = f"Flow {key} has {flow_data['packet_count']} packets, average size {average_packet_size} bytes."
        alert("High Packet Count Anomaly", key[0], alert_detail)

def update_flow(pkt):
    if IP in pkt and (TCP in pkt or UDP in pkt):
        layer = TCP if TCP in pkt else UDP
        key = (pkt[IP].src, pkt[IP].dst, pkt[layer].sport, pkt[layer].dport, pkt[IP].proto)
        flow_data = flows[key]
        now = datetime.now()

        # Update flow statistics
        flow_data['packet_count'] += 1
        flow_data['byte_count'] += len(pkt)
        flow_data['timestamps'].append(now)
        flow_data['src_ports'].add(pkt[layer].sport)
        flow_data['dst_ports'].add(pkt[layer].dport)

        if flow_data['start_time'] is None:
            flow_data['start_time'] = now
        flow_data['end_time'] = now

        analyze_flow(key, flow_data)

# Start packet sniffing
# sniff(prn=update_flow)
