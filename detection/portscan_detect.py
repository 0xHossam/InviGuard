module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module leverages Scapy to monitor and analyze network traffic for signs of port scanning, \
             utilizing TCP, UDP, and various TCP flag combinations to identify scanning techniques.",
    "Title": "Network Port Scan Detection Module",
    "Date": "21 MAR 2024",
    "Category": "Intrusion Detection",
    "Description": "Designed to detect port scanning activities, this module identifies different scanning methods including SYN, \
                    FIN, NULL, XMAS, and UDP scans. It alerts upon detecting suspicious patterns indicative of scanning.",
    "References": [
        "https://nmap.org/book/man-port-scanning-techniques.html",  # Nmap Port Scanning Techniques
        "https://www.scapy.net",  # Scapy Documentation
    ]

}

from scapy.all import TCP, IP, UDP
from collections import defaultdict
from time import time
from alerter.alert import alert

scan_stats = defaultdict(lambda: {
    'SYN': 0, 'SYN-ACK': 0, 'FIN': 0, 'NULL': 0, 'XMAS': 0, 'UDP': 0,
    'ports': set(),  
    'timestamps': [] 
})

def tcp_flags(tcp_segment):
    flags = {
        'FIN': 0x01, 'SYN': 0x02, 'RST': 0x04, 'PSH': 0x08,
        'ACK': 0x10, 'URG': 0x20, 'ECE': 0x40, 'CWR': 0x80
    }
    
    return {flag for flag, bit in flags.items() if tcp_segment.flags & bit}

def update_scan_stats(ip, pkt):
    stats = scan_stats[ip]
    
    if TCP in pkt:
        flags = tcp_flags(pkt[TCP])
        
        # increamenting the appropriate counters based on the TCP flags
        if 'SYN' in flags and 'ACK' not in flags:
            stats['SYN'] += 1
        elif 'SYN' in flags and 'ACK' in flags:
            stats['SYN-ACK'] += 1
        elif 'FIN' in flags:
            stats['FIN'] += 1
        elif not flags:  # NULL scan check
            stats['NULL'] += 1
        elif flags == {'FIN', 'PSH', 'URG'}:  # XMAS scan check
            stats['XMAS'] += 1

        stats['ports'].add(pkt[TCP].dport)
    
    elif UDP in pkt:
        stats['UDP'] += 1
        stats['ports'].add(pkt[UDP].dport)
    
    stats['timestamps'].append(time())

def is_suspicious_activity(ip, min_ports_scanned=20, time_window=300):
    stats = scan_stats[ip]
    recent_activity = [ts for ts in stats['timestamps'] if time() - ts < time_window]
    if len(stats['ports']) >= min_ports_scanned and len(recent_activity) >= min_ports_scanned:
        return True
    return False

def detect_port_scan(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        update_scan_stats(src_ip, pkt)
        if is_suspicious_activity(src_ip):
            details = (f"Ports scanned: {len(scan_stats[src_ip]['ports'])}, "
                       f"SYN: {scan_stats[src_ip]['SYN']}, SYN-ACK: {scan_stats[src_ip]['SYN-ACK']}, "
                       f"FIN: {scan_stats[src_ip]['FIN']}, NULL: {scan_stats[src_ip]['NULL']}, "
                       f"XMAS: {scan_stats[src_ip]['XMAS']}, UDP: {scan_stats[src_ip]['UDP']}")
            alert("Port Scanning Detected", src_ip, details)

            # resetting the stats for the IP after detection
            scan_stats[src_ip] = defaultdict(lambda: {'SYN': 0, 'SYN-ACK': 0, 'FIN': 0, 'NULL': 0, 'XMAS': 0, 'UDP': 0, 'ports': set(), 'timestamps': []})
