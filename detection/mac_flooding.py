from scapy.all import Ether
from collections import defaultdict, deque
from alerter.alert import alert
import datetime
from configs.config_loader import load_config

# Load configuration
config = load_config()
mac_flooding_config = config.get( 'mac_flooding', {} )

# Configuration parameters
alert_threshold = mac_flooding_config.get( 'alert_threshold', 1.5 )  # Multiplier for the average MAC count to trigger an alert
history_maxlen = mac_flooding_config.get( 'history_maxlen', 1000 )  # Maximum length of history to keep track of MAC addresses
count_maxlen = mac_flooding_config.get( 'count_maxlen', 100 )  # Maximum length of the deque that stores unique MAC counts

# History of MAC addresses and counts of unique MACs
mac_history = defaultdict( lambda: deque( maxlen = history_maxlen ) )
mac_counts = deque( maxlen = count_maxlen )

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects MAC flooding attacks by monitoring the number of unique MAC addresses seen on the network within a short period. \
             MAC flooding aims to overwhelm a switch's MAC table, causing it to operate as a hub and broadcast all traffic.",
    "Title": "MAC Flooding Detection Module",
    "Date": "19 MAY 2024",
    "Category": "Network Security",
    "Description": "This module detects MAC flooding attacks by tracking the number of unique MAC addresses observed in network traffic over a \
                    short time interval. If the number of unique MAC addresses exceeds a dynamically calculated threshold, an alert is triggered.",
    "References": [
        "https://en.wikipedia.org/wiki/MAC_flooding",  # MAC Flooding - Wikipedia
        "https://www.sans.org/reading-room/whitepapers/threats/mac-flooding-attacks-defenses-36017"  # MAC Flooding Attacks and Defenses
    ]
}

def detect_mac_flooding( pkt ):

    if pkt.haslayer( Ether ):
        src_mac = pkt[ Ether ].src
        current_time = datetime.datetime.now()
        mac_history[ current_time ].append( src_mac )

        # Calculate the number of unique MAC addresses
        unique_macs = set( mac for macs in mac_history.values() for mac in macs )
        mac_counts.append( len( unique_macs ) )

        if len( mac_counts ) == mac_counts.maxlen:
            avg_mac_count = sum( mac_counts ) / len( mac_counts )
            current_count = len( unique_macs )

            if current_count > avg_mac_count * alert_threshold:
                alert( "MAC Flooding Detected", "", f"Number of unique MAC addresses: { current_count } exceeds average: { avg_mac_count }" )
