from scapy.all import Ether, ARP
from collections import defaultdict, deque
from alerter.alert import alert
import datetime
from configs.config_loader import load_config

# Load configuration
config = load_config()
mac_spoofing_config = config.get( 'mac_spoofing', {} )

change_threshold = mac_spoofing_config.get( 'change_threshold', 5 )  
history_maxlen = mac_spoofing_config.get( 'history_maxlen', 100 )  
mac_ip_history = defaultdict( lambda: { "macs": set(), "timestamps": deque( maxlen = history_maxlen ) } )
ip_mac_history = defaultdict( lambda: { "ips": set(), "timestamps": deque( maxlen = history_maxlen ) } )

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects MAC spoofing attacks by monitoring changes in MAC addresses associated with IP addresses over time. \
             MAC spoofing can be used to bypass security controls or impersonate devices.",
    "Title": "MAC Spoofing Detection Module",
    "Date": "19 MAY 2024",
    "Category": "Network Security",
    "Description": "This module detects MAC spoofing by tracking the MAC addresses associated with IP addresses. When a different MAC address is \
                    detected for an IP address, an alert is triggered.",
    "References": [
        "https://en.wikipedia.org/wiki/MAC_spoofing",  # MAC Spoofing - Wikipedia
        "https://www.sans.org/reading-room/whitepapers/threats/mac-spoofing-detecting-preventing-37067"  # MAC Spoofing: Detecting and Preventing
    ]

}

def detect_mac_spoofing( pkt ):

    if pkt.haslayer( ARP ):
        src_ip, src_mac = pkt[ ARP ].psrc, pkt[ ARP ].hwsrc
        current_time = datetime.datetime.now()

        # upodate the MAC history for the IP
        mac_entry = mac_ip_history[ src_ip ]
        if src_mac not in mac_entry[ "macs" ]:
            
            if mac_entry[ "macs" ]:
                alert_details = f"Previous MACs: { ', '.join( mac_entry[ 'macs' ] ) }, New MAC: { src_mac }"
                alert( "MAC Spoofing Detected", src_ip, alert_details )

            mac_entry[ "macs" ].add( src_mac )
            mac_entry[ "timestamps" ].append( current_time )

        # upodate IP history for the MAC
        ip_entry = ip_mac_history[ src_mac ]
        if src_ip not in ip_entry[ "ips" ]:
            if ip_entry[ "ips" ]:
                alert_details = f"Previous IPs: { ', '.join( ip_entry[ 'ips' ] ) }, New IP: { src_ip }"
                alert( "MAC Spoofing Detected", src_mac, alert_details )
            ip_entry[ "ips" ].add( src_ip )
            ip_entry[ "timestamps" ].append( current_time )

        # checking for frequent MAC changes for the same IP
        if len( mac_entry[ "timestamps" ] ) == mac_entry[ "timestamps" ].maxlen:
            time_diffs = [ ( mac_entry[ "timestamps" ][ i ] - mac_entry[ "timestamps" ][ i - 1 ] ).total_seconds() for i in range( 1, len( mac_entry[ "timestamps" ] ) ) ]
            avg_change_time = sum( time_diffs ) / len( time_diffs )

            if avg_change_time < change_threshold:
                alert( "Frequent MAC Changes Detected", src_ip, f"MAC address changes average interval: { avg_change_time } seconds" )

        # checking for frequent IP changes for the same MAC
        if len( ip_entry[ "timestamps" ] ) == ip_entry[ "timestamps" ].maxlen:
            time_diffs = [ ( ip_entry[ "timestamps" ][ i ] - ip_entry[ "timestamps" ][ i - 1 ] ).total_seconds() for i in range( 1, len( ip_entry[ "timestamps" ] ) ) ]
            avg_change_time = sum( time_diffs ) / len( time_diffs )

            if avg_change_time < change_threshold:
                alert( "Frequent IP Changes Detected", src_mac, f"IP address changes average interval: { avg_change_time } seconds" )
