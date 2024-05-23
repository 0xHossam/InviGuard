from scapy.all import IP, sniff
from alerter.alert import alert
import requests

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects traffic to and from Tor exit nodes, which may indicate anonymized or suspicious communication.",
    "Title": "Tor Exit Node Detection Module",
    "Date": "02 APR 2024",
    "Category": "Network Security",
    "Description": "The Tor Exit Node Detection Module monitors network traffic for connections to known Tor exit nodes. Identifying these connections helps in detecting anonymized communication that could be used for malicious purposes.",
    "References": [
        "https://www.torproject.org/",  # The Tor Project
        "https://www.sans.org/reading-room/whitepapers/detection/detecting-preventing-abuse-tor-exit-nodes-36747",  # Detecting and Preventing Abuse of Tor Exit Nodes
    ]

}

def get_tor_exit_nodes():

    try:
        response = requests.get( "https://check.torproject.org/exit-addresses" )
        exit_nodes = [ line.split()[ 1 ] for line in response.text.split( '\n' ) if line.startswith( "ExitAddress" ) ]
        return set( exit_nodes )
    except Exception as e:
        print( f"Error fetching Tor exit nodes: { e }" )
        return set()

tor_exit_nodes = get_tor_exit_nodes()

def detect_tor_traffic( pkt ):

    if pkt.haslayer( IP ):
        src_ip = pkt[ IP ].src
        dst_ip = pkt[ IP ].dst
        if src_ip in tor_exit_nodes or dst_ip in tor_exit_nodes:
            alert( "Tor Exit Node Traffic Detected", src_ip, f"Traffic to/from Tor exit node detected: { dst_ip if src_ip in tor_exit_nodes else src_ip }" )
