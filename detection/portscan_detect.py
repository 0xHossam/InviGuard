import datetime
import logging
from scapy.all import TCP, IP, UDP
from collections import defaultdict
from time import time
from alerter.alert import alert

logging.basicConfig( level = logging.INFO, format = '%(asctime)s - %(levelname)s - %(message)s' )

module_info = {
    "Author": "Hossam Ehab",
    "Info": "This module leverages Scapy to monitor and analyze network traffic for signs of port scanning, "
            "utilizing TCP, UDP, and various TCP flag combinations to identify scanning techniques.",
    "Title": "Network Port Scan Detection Module",
    "Date": "21 MAR 2024",
    "Category": "Intrusion Detection",
    "Description": "Designed to detect port scanning activities, this module identifies different scanning methods including SYN, "
                   "FIN, NULL, XMAS, ACK, and UDP scans. It alerts upon detecting suspicious patterns indicative of scanning.",
    "References": [
        "https://nmap.org/book/man-port-scanning-techniques.html",  # Nmap Port Scanning Techniques
        "https://www.scapy.net",  # Scapy Documentation
    ]
}

scan_stats = defaultdict( lambda: {
    'SYN': 0, 'SYN-ACK': 0, 'FIN': 0, 'NULL': 0, 'XMAS': 0, 'ACK': 0, 'UDP': 0,
    'ports': set( ),  
    'timestamps': [ ]
} )

MIN_PORTS_SCANNED = 20
TIME_WINDOW = 300  # in seconds
RATE_THRESHOLD = 10  # packets per second

def tcp_flags( tcp_segment ):

    flags = {
        'FIN': 0x01, 'SYN': 0x02, 'RST': 0x04, 'PSH': 0x08,
        'ACK': 0x10, 'URG': 0x20, 'ECE': 0x40, 'CWR': 0x80
    }
    
    return { flag for flag, bit in flags.items( ) if tcp_segment.flags & bit }

def update_scan_stats( ip, pkt ):

    stats = scan_stats[ ip ]
    
    if TCP in pkt:
        flags = tcp_flags( pkt[ TCP ] )
        
        # Incrementing the appropriate counters based on the TCP flags
        if 'SYN' in flags and 'ACK' not in flags:
            stats[ 'SYN' ] += 1
        elif 'SYN' in flags and 'ACK' in flags:
            stats[ 'SYN-ACK' ] += 1
        elif 'FIN' in flags:
            stats[ 'FIN' ] += 1
        elif not flags:  # NULL scan check
            stats[ 'NULL' ] += 1
        elif flags == { 'FIN', 'PSH', 'URG' }:  # XMAS scan check
            stats[ 'XMAS' ] += 1
        elif 'ACK' in flags and len( flags ) == 1:  # ACK scan check
            stats[ 'ACK' ] += 1

        stats[ 'ports' ].add( pkt[ TCP ].dport )
    
    elif UDP in pkt:
        stats[ 'UDP' ] += 1
        stats[ 'ports' ].add( pkt[ UDP ].dport )
    
    stats[ 'timestamps' ].append( time( ) )

def is_suspicious_activity( ip, min_ports_scanned = MIN_PORTS_SCANNED, time_window = TIME_WINDOW, rate_threshold = RATE_THRESHOLD ):

    stats = scan_stats[ ip ]
    current_time = time( )
    recent_activity = [ ts for ts in stats[ 'timestamps' ] if current_time - ts < time_window ]
    
    if len( stats[ 'ports' ] ) >= min_ports_scanned and len( recent_activity ) >= min_ports_scanned:
        rate = len( recent_activity ) / time_window
        if rate > rate_threshold:
            return True
    return False

def reset_stats( ip ):

    scan_stats[ ip ] = {
        'SYN': 0, 'SYN-ACK': 0, 'FIN': 0, 'NULL': 0, 'XMAS': 0, 'ACK': 0, 'UDP': 0, 'ports': set( ), 'timestamps': [ ]
    }

def detect_port_scan( pkt ):

    if IP in pkt:
        src_ip = pkt[ IP ].src
        try:
            update_scan_stats( src_ip, pkt )
            if is_suspicious_activity( src_ip ):
                details = ( f"Ports scanned: { len( scan_stats[ src_ip ][ 'ports' ] ) }, "
                           f"SYN: { scan_stats[ src_ip ][ 'SYN' ] }, SYN-ACK: { scan_stats[ src_ip ][ 'SYN-ACK' ] }, "
                           f"FIN: { scan_stats[ src_ip ][ 'FIN' ] }, NULL: { scan_stats[ src_ip ][ 'NULL' ] }, "
                           f"XMAS: { scan_stats[ src_ip ][ 'XMAS' ] }, ACK: { scan_stats[ src_ip ][ 'ACK' ] }, UDP: { scan_stats[ src_ip ][ 'UDP' ] }" )
                alert( "Port Scanning Detected", src_ip, details )
                logging.info( f"Alert: Port Scanning Detected from { src_ip }. Details: { details }" )
                reset_stats( src_ip )
        except Exception as e:
            pass