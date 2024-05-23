from scapy.all import sniff, ICMP, IP
from alerter.alert import alert
from collections import defaultdict
import datetime

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module monitors for ICMP tunneling by analyzing ICMP packet patterns.",
    "Title": "ICMP Tunneling Detection Module",
    "Date": "18 MAY 2024",
    "Category": "Network Security",
    "Description": "Detects ICMP tunneling by analyzing ICMP packet patterns for signs of data exfiltration or covert communication.",
    "References": [
        "https://en.wikipedia.org/wiki/ICMP_tunnel",
        "https://www.sans.org/reading-room/whitepapers/detection/icmp-tunnels-description-detection-defense-34152",
    ]

}

def entropy( data ):

    from collections import Counter
    import math
    
    if not data:
        return 0
    
    counter = Counter( data )
    entropy = 0
    
    for count in counter.values():
        p = count / len( data )
        entropy -= p * math.log2( p )
    
    return entropy

icmp_history = defaultdict( list )

def detect_icmp_tunneling( pkt ):

    if pkt.haslayer( ICMP ) and pkt[ ICMP ].type == 8:  # ICMP Echo Request
        src_ip = pkt[ IP ].src
        icmp_id = pkt[ ICMP ].id
        packet_size = len( pkt )
        current_time = datetime.datetime.now()
        
        icmp_history[ src_ip ].append( { "id": icmp_id, "size": packet_size, "timestamp": current_time } )

        # checking for unusual size of ICMP packets
        if packet_size > 100:
            alert( "ICMP Tunneling Detected", src_ip, f"Suspicious ICMP packet size detected: { packet_size } bytes" )

        # checking for high frequency of ICMP packets from the same source
        packet_times = [ entry["timestamp"] for entry in icmp_history[ src_ip ] ]
        time_diffs = [ packet_times[ i ] - packet_times[ i - 1 ] for i in range( 1, len( packet_times ) ) ]
        frequent_packets = any( diff.total_seconds() < 5 for diff in time_diffs )

        if frequent_packets:
            alert( "Frequent ICMP Packets", src_ip, "Frequent ICMP packets detected, indicating potential ICMP tunneling." )

        # checking for high entropy in ICMP data payload
        icmp_payload = str(pkt[ICMP].payload)
        if entropy( icmp_payload ) > 4.0:
            alert( "ICMP Tunneling Detected", src_ip, f"High entropy in ICMP payload detected: { icmp_payload }" )



