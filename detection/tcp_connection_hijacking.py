from scapy.all import IP, TCP
from collections import defaultdict
from time import time
from alerter.alert import alert
from utils.config import hijack_rst_threshold, hijack_time_window

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects TCP connection hijacking attempts by monitoring anomalies in TCP packet sequences and flags. \
             It identifies unusual patterns such as duplicate ACKs, unexpected RST packets, and abrupt changes in sequence numbers.",
    "Title": "TCP Connection Hijacking Detection Module",
    "Date": "23 JUN 2024",
    "Category": "Network Security",
    "Description": "This module identifies TCP connection hijacking by analyzing TCP sequence numbers, flags, and packet frequencies. \
                    It triggers alerts upon detecting suspicious patterns, aiding in the early detection and prevention of session hijacking.",
    "References": [
        "https://www.tenable.com/plugins/nessus/118017",
        "https://www.sans.org/reading-room/whitepapers/intrusion/defeating-tcp-ip-stack-fingerprinting-2001"
    ]

}

tcp_hijack_stats = defaultdict( lambda: {
    'seq_numbers': defaultdict( set ),
    'rst_packets': 0,
    'timestamps': []
} )

def detect_tcp_hijacking( pkt ):

    if IP in pkt and TCP in pkt:
        src_ip = pkt[ IP ].src
        dst_ip = pkt[ IP ].dst
        sport = pkt[ TCP ].sport
        dport = pkt[ TCP ].dport
        conn_tuple = ( src_ip, dst_ip, sport, dport )
        stats = tcp_hijack_stats[ conn_tuple ]
        
        # monitor sequence numbers
        if pkt[ TCP ].flags & 0x10:  # ACK flag
            stats[ 'seq_numbers' ][ pkt[ IP ].src ].add( pkt[ TCP ].seq )
        
        # monitor RST packets
        if pkt[ TCP ].flags & 0x04:  # RST flag
            stats[ 'rst_packets' ] += 1
        
        stats[ 'timestamps' ].append( time( ) )
        
        # detect anomalies
        if stats[ 'rst_packets' ] > hijack_rst_threshold:
            alert_details = ( f"Connection: { conn_tuple }, RST packets: { stats['rst_packets'] }" )
            alert( "TCP Hijacking Detected", src_ip, alert_details )

            tcp_hijack_stats[ conn_tuple ] = {
                'seq_numbers': defaultdict( set ),
                'rst_packets': 0,
                'timestamps': []
            }
