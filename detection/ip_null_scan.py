from scapy.all import IP, TCP
from collections import deque
from alerter.alert import alert
import datetime
from configs.config_loader import load_config

# Load configuration
config = load_config()
ip_null_scan_config = config.get( 'ip_null_scan', {} )

alert_threshold = ip_null_scan_config.get( 'alert_threshold', 2 )  
count_maxlen = ip_null_scan_config.get( 'count_maxlen', 100 )  
null_scan_counts = deque( maxlen = count_maxlen )

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects IP Null scans, which are used by attackers to probe for open ports on a target system by sending packets \
             with no set flags.",
    "Title": "IP Null Scan Detection Module",
    "Date": "19 MAY 2024",
    "Category": "Network Security",
    "Description": "This module detects IP Null scans by identifying TCP packets with no flags set. Such packets are often used in reconnaissance \
                    activities to identify open ports on a target system.",
    "References": [
        "https://en.wikipedia.org/wiki/Port_scanner#Types_of_scan",  # Port Scanner - Wikipedia
        "https://www.sans.org/reading-room/whitepapers/auditing/tcp-syn-port-scanning-techniques-42"  # TCP SYN and Port Scanning Techniques
    ]
}

def detect_ip_null_scan( pkt ):

    if pkt.haslayer( TCP ):
        tcp_flags = pkt[ TCP ].flags
        if tcp_flags == 0:
            current_time = datetime.datetime.now()
            null_scan_counts.append( current_time )

            if len( null_scan_counts ) == null_scan_counts.maxlen:
                time_diffs = [ ( null_scan_counts[ i ] - null_scan_counts[ i - 1 ] ).total_seconds() for i in range( 1, len( null_scan_counts ) ) ]
                avg_scan_interval = sum( time_diffs ) / len( time_diffs )

                current_interval = ( current_time - null_scan_counts[ 0 ] ).total_seconds() / len( null_scan_counts )

                if current_interval < avg_scan_interval / alert_threshold:
                    alert( "IP Null Scan Detected", pkt[ IP ].src, f"Detected unusually frequent null scans. Current interval: { current_interval } seconds" )
