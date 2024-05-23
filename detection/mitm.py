from scapy.all import ARP
from alerter.alert import alert
import datetime
from collections import defaultdict

module_info = {
    "Author": "Hossam Ehab",
    "Info": "This module detects MITM attacks by monitoring ARP traffic.",
    "Title": "MITM Detection Module",
    "Date": "18 MAR 2024",
    "Category": "Network Security",
    "Description": "The module detects MITM attacks using ARP spoofing indicators.",
    "References": [
        "https://en.wikipedia.org/wiki/ARP_spoofing",
        "https://en.wikipedia.org/wiki/Man-in-the-middle_attack",
    ]
}

arp_history = defaultdict( lambda: { "macs": set(), "timestamps": [], "latency": [] } )

def detect_mitm( pkt ):

    if pkt.haslayer( ARP ):
        src_ip = pkt[ ARP ].psrc
        src_mac = pkt.src
        current_time = datetime.datetime.now()

        arp_entry = arp_history[ src_ip ]
        arp_entry[ "macs" ].add( src_mac )
        arp_entry[ "timestamps" ].append( current_time )

        if len( arp_entry[ "macs" ] ) > 1:
            alert_details = f"Multiple MACs detected for IP { src_ip }: {', '.join( arp_entry[ 'macs' ] )}"
            alert( "MITM Detected", src_ip, alert_details )

        if len( arp_entry[ "timestamps" ] ) > 1:
            time_diffs = [ ( arp_entry[ "timestamps" ][ i ] - arp_entry[ "timestamps" ][ i - 1 ] ).total_seconds() for i in range( 1, len( arp_entry[ "timestamps" ] ) ) ]
            if any( diff < 60 for diff in time_diffs ):
                alert_details = f"ARP spoofing detected for IP { src_ip }: New MAC { src_mac }, Previous MACs {arp_entry['macs']}"
                alert( "MITM Detected", src_ip, alert_details )

        if len( arp_entry[ "timestamps" ] ) > 1:
            latency = ( current_time - arp_entry[ "timestamps" ][ -2 ] ).total_seconds()
            arp_entry[ "latency" ].append( latency )
            if len( arp_entry[ "latency" ] ) > 10:
                avg_latency = sum( arp_entry[ "latency" ] ) / len( arp_entry[ "latency" ] )
                if latency > avg_latency * 2:
                    alert_details = f"Unusual network latency detected for IP { src_ip }: Current latency { latency } seconds, Average latency { avg_latency } seconds"
                    alert( "MITM Detected", src_ip, alert_details )
