from scapy.all import IP, TCP, Raw
from collections import defaultdict
from alerter.alert import alert
import datetime

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects HTTP/S beaconing behavior in network traffic. Beaconing is a technique used by malware to communicate with C2 servers at regular intervals.",
    "Title": "HTTP/S Beaconing Detection Module",
    "Date": "26 MAR 2024",
    "Category": "Network Security",
    "Description": "The HTTP/S Beaconing Detection Module identifies periodic HTTP or HTTPS requests to the same IP address, which is indicative of beaconing behavior. This module monitors the intervals between requests and raises an alert if regular, frequent connections are detected.",
    "References": [
        "https://www.sans.org/reading-room/whitepapers/detection/advanced-threat-detection-beaconing-covert-channel-analysis-36532",  # Advanced Threat Detection
        "https://attack.mitre.org/techniques/T1071/001/",  # MITRE ATT&CK - Application Layer Protocol: Web Protocols
    ]

}

beaconing_history = defaultdict( 

    lambda: { "timestamps": [], "intervals": [] }

)

def detect_http_beaconing( pkt ):

    if pkt.haslayer( IP ) and pkt.haslayer( TCP ) and pkt.haslayer( Raw ):
        
        if b"HTTP" in pkt[ Raw ].load or b"HTTPS" in pkt[ Raw ].load:
            src_ip = pkt[ IP ].src
            dst_ip = pkt[ IP ].dst
            current_time = datetime.datetime.now()

            beaconing_entry = beaconing_history[ ( src_ip, dst_ip ) ]
            beaconing_entry[ "timestamps" ].append( current_time )

            if len( beaconing_entry[ "timestamps" ] ) > 1:
                time_diff = ( beaconing_entry[ "timestamps" ][ -1 ] - beaconing_entry[ "timestamps" ][ -2 ] ).total_seconds()
                beaconing_entry[ "intervals" ].append( time_diff )

                if len( beaconing_entry[ "intervals" ] ) > 5:  # checking after the first 5 intervals to reduce false positives
                    average_interval = sum( beaconing_entry[ "intervals" ] ) / len( beaconing_entry[ "intervals" ] )

                    if all( abs( interval - average_interval ) < 2 for interval in beaconing_entry[ "intervals" ] ):  # allow a small deviation
                        alert( "HTTP/S Beaconing Detected", src_ip, f"Regular intervals of HTTP/S communication detected with { dst_ip }" )
