from scapy.all import sniff, IP, TCP, Raw
from collections import defaultdict
from time import time
from alerter.alert import alert
from utils.config import post_exfil_threshold, post_data_threshold, post_time_window

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects HTTP POST data exfiltration by monitoring POST requests for unusual patterns and large data transfers. \
             It identifies frequent or large POST requests, which could indicate unauthorized data exfiltration.",
    "Title": "HTTP POST Exfiltration Detection Module",
    "Date": "11 JUN 2024",
    "Category": "Data Security",
    "Description": "This module monitors HTTP POST requests to detect potential data exfiltration. \
                    It analyzes POST request frequency, data size, and destination IPs to identify suspicious activities and trigger alerts.",
    "References": [
        "https://www.sans.org/reading-room/whitepapers/detection/http-post-requests-detect-data-exfiltration-34640",
        "https://www.tenable.com/plugins/nessus/118017"
    ]

}

http_post_stats = defaultdict( lambda: {
    'post_requests': 0,
    'total_data': 0,
    'timestamps': [],
    'dest_ips': set()
} )

HTTP_PORT = 80

def detect_http_post_exfiltration( pkt ):

    if IP in pkt and TCP in pkt and pkt[ TCP ].dport == HTTP_PORT and Raw in pkt:
    
        payload = pkt[ Raw ].load.decode( 'utf-8', errors = 'ignore' )
        if 'POST' in payload:
            src_ip = pkt[ IP ].src
            dst_ip = pkt[ IP ].dst
            stats = http_post_stats[ src_ip ]
            
            # update stats
            stats[ 'post_requests' ] += 1
            stats[ 'total_data' ] += len( payload )
            stats[ 'timestamps' ].append( time( ) )
            stats[ 'dest_ips' ].add( dst_ip )
            
            current_time = time( )
            recent_posts = [ ts for ts in stats[ 'timestamps' ] if current_time - ts < post_time_window ]
            if stats[ 'total_data' ] > post_data_threshold or len( recent_posts ) > post_exfil_threshold:
                alert_details = ( f"IP: { src_ip }, Total Data: { stats['total_data'] } bytes, "
                                  f"POST Requests: { len( recent_posts ) }, Unique Dest IPs: { len( stats['dest_ips'] ) }" )
                alert( "HTTP POST Exfiltration Detected", src_ip, alert_details )
                
                # reset stats
                http_post_stats[ src_ip ] = {
                    'post_requests': 0,
                    'total_data': 0,
                    'timestamps': [],
                    'dest_ips': set()
                }

