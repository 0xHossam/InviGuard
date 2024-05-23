from scapy.all import sniff, IP, TCP
from alerter.alert import alert
from collections import defaultdict, Counter
import datetime

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects P2P C2 communication patterns by analyzing network traffic for peer-to-peer protocol usage and unusual peer connections.",
    "Title": "P2P C2 Communication Detection Module",
    "Date": "21 MAY 2024",
    "Category": "Network Security",
    "Description": "Detects P2P C2 communication by monitoring for peer-to-peer protocol usage and analyzing the frequency and patterns of peer connections.",
    "References": [
        "https://en.wikipedia.org/wiki/Peer-to-peer",
        "https://www.sans.org/reading-room/whitepapers/malicious/peer-to-peer-command-control-33874"
    ]

}

p2p_ports = [ 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6890, 6891, 6892, 6893, 6894, 6895, 6896, 6897, 6898, 6899, 51413 ]
peer_history = defaultdict( lambda: defaultdict( list ) )

def detect_p2p_c2_communication( pkt ):

    if IP in pkt and TCP in pkt and pkt[ TCP ].dport in p2p_ports:
        
        src_ip = pkt[ IP ].src
        dst_ip = pkt[ IP ].dst
        current_time = datetime.datetime.now()

        peer_history[ src_ip ][ dst_ip ].append( current_time )
        peer_connections = peer_history[ src_ip ]

        # checking if the number of connections to different peers is unusually high
        if len(peer_connections) > 10:  # number of unique peers

            alert("P2P Communication Detected", src_ip, f"Unusual number of peer connections detected that could be C2 communication: {len(peer_connections)} peers.")
            peer_history[src_ip] = defaultdict(list)

