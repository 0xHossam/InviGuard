from scapy.all import IP
from alerter.alert import alert
from collections import defaultdict, deque
from utils.config import trusted_network_prefixes, suspicious_threshold, time_window, ttl_threshold
import datetime

module_info = {
    "Author": "Hossam Ehab",
    "Info": "This module monitors for IP spoofing by analyzing inconsistencies in IP packet source addresses.",
    "Title": "IP Spoofing Detection Module",
    "Date": "20 MAY 2024",
    "Category": "Network Security",
    "Description": "Detects IP spoofing by monitoring for IP address inconsistencies and unusual patterns in IP packet sources.",
    "References": [
        "https://en.wikipedia.org/wiki/IP_address_spoofing",
        "https://www.us-cert.gov/ncas/tips/ST04-015"
    ]
}

ip_history = defaultdict(lambda: deque(maxlen=100))

def detect_ip_spoofing(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl = pkt[IP].ttl
        current_time = datetime.datetime.now()
        
        # Check if the source IP is within the trusted network prefixes
        if not any(src_ip.startswith(prefix) for prefix in trusted_network_prefixes):
            ip_history[src_ip].append((current_time, ttl))
            request_times = [entry[0] for entry in ip_history[src_ip]]
            ttl_values = [entry[1] for entry in ip_history[src_ip]]
            
            # Check the number of requests in the defined time window
            if len(request_times) > suspicious_threshold:
                window_start = request_times[0]
                if (current_time - window_start).total_seconds() < time_window:
                    alert("IP Spoofing Detected", src_ip, f"Suspicious IP packet activity detected: {len(request_times)} packets in {time_window} seconds.")
                    ip_history[src_ip].clear()
            
            # Check for significant TTL differences indicating spoofed packets
            if max(ttl_values) - min(ttl_values) > ttl_threshold:
                alert("IP Spoofing Detected", src_ip, f"Significant TTL differences detected in packets from {src_ip}: TTL values vary by more than {ttl_threshold}.")

