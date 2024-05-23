from scapy.all import ARP
from alerter.alert import alert
from collections import defaultdict
import datetime

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module actively monitors for ARP spoofing attacks within the network. It detects ARP spoofing by tracking \
             the association of MAC addresses to IP addresses over time. Alerts are generated for new MAC associations, \
             unusual ARP response frequency, and multiple MAC addresses associated with a single IP address, which could \
             indicate ARP cache poisoning or spoofing activities.",
    "Title": "ARP Spoofing Detection Module",
    "Date": "18 MAR 2024",
    "Category": "Network Security",
    "Description": "Designed to enhance network security, this module detects ARP spoofing by analyzing ARP traffic. It keeps \
                    track of MAC-IP associations and identifies suspicious activities such as the introduction of new MAC \
                    addresses for known IPs, frequent ARP responses, and the detection of multiple MAC addresses for a single \
                    IP. Such activities often signal ARP spoofing attacks, enabling early detection and prevention.",
    "References": [
        "https://en.wikipedia.org/wiki/ARP_spoofing",  # ARP spoofing - Wikipedia
        "https://www.sans.org/reading-room/whitepapers/networkdevs/arp-spoofing-introduction-arp-cache-poisoning-1051",  # An Introduction to ARP Spoofing
    ]
    
}

arp_history = defaultdict( 
    lambda: 
        {
            "macs": set(), 
            "last_update": None, 
            "timestamps": []
        }
)

def detect_arp_spoofing( pkt ):

    if pkt.haslayer( ARP ) and pkt[ ARP ].op == 2:

        src_ip, src_mac = pkt[ ARP ].psrc, pkt.src
        arp_entry = arp_history[src_ip]
        current_time = datetime.datetime.now()
        
        arp_entry["last_update"] = current_time
        arp_entry["timestamps"].append( current_time )
        
        if src_mac not in arp_entry["macs"]:

            if arp_entry["macs"]:

                alert_details = f"Previous MACs: {', '.join( arp_entry['macs'] )}, New MAC: { src_mac }"
                alert("ARP Spoofing Detected", src_ip, alert_details)
            
            arp_entry["macs"].add( src_mac )
        
        if len(arp_entry["timestamps"]) > 1:

            time_diffs = [ arp_entry["timestamps"] [ i ] - arp_entry["timestamps"] [ i - 1 ] for i in range( 1, len(arp_entry["timestamps"]) )]
            unusual_frequency = any(diff.total_seconds() < 10 for diff in time_diffs)  
            
            if unusual_frequency:
                alert("Unusual ARP Response Frequency", src_ip, "Possible ARP spoofing due to frequent ARP responses.")
        
        if len(arp_entry["macs"]) > 1:
            alert("Multiple MACs Detected", src_ip, f"Multiple MAC addresses ({', '.join( arp_entry['macs'] )}) detected for the same IP.")
        
        if len(arp_entry["macs"]) > 5:
            alert("Potential ARP Cache Poisoning", src_ip, f"Multiple MAC addresses ({', '.join( arp_entry['macs'] )}) detected for the same IP. Possible ARP cache poisoning.")
