from scapy.all import IP, TCP
from collections import deque
from alerter.alert import alert
import datetime
import numpy as np
from configs.config_loader import load_config

# Load configuration
config = load_config()
rst_fin_flood_config = config.get( 'rst_fin_flood', {} )

# Configuration parameters
alert_multiplier = rst_fin_flood_config.get( 'alert_multiplier', 3 )  # Multiplier for the standard deviation-based threshold to trigger an alert
rate_maxlen = rst_fin_flood_config.get( 'rate_maxlen', 100 )  # Maximum length of history to keep track of RST/FIN packet rates

# History of RST/FIN packet rates
rst_fin_rate = deque( maxlen = rate_maxlen )

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects RST/FIN flood attacks by monitoring the rate of TCP RST and FIN packets in the network. \
             High rates of such packets can indicate a denial-of-service attack aimed at disrupting active connections.",
    "Title": "RST/FIN Flood Attack Detection Module",
    "Date": "19 MAY 2024",
    "Category": "Network Security",
    "Description": "This module detects RST/FIN flood attacks by tracking the rate of TCP RST and FIN packets. If the rate exceeds a \
                    dynamically calculated threshold based on historical data, an alert is triggered.",
    "References": [
        "https://en.wikipedia.org/wiki/Denial-of-service_attack#TCP_reset_attack",  # TCP Reset Attack - Wikipedia
        "https://www.sans.org/reading-room/whitepapers/detection/understanding-detecting-tcp-reset-attacks-37945"  # Understanding and Detecting TCP Reset Attacks
    ]
}

def detect_rst_fin_flood( pkt ):

    if pkt.haslayer( TCP ):
        if pkt[ TCP ].flags & 0x04 or pkt[ TCP ].flags & 0x01:  # Check for RST or FIN flag
            current_time = datetime.datetime.now()
            rst_fin_rate.append( current_time )

            if len( rst_fin_rate ) == rst_fin_rate.maxlen:
                time_diffs = [ ( rst_fin_rate[ i ] - rst_fin_rate[ i - 1 ] ).total_seconds() for i in range( 1, len( rst_fin_rate ) ) ]
                avg_rate = len( rst_fin_rate ) / sum( time_diffs )
                std_dev = np.std( time_diffs )

                current_rate = 1 / ( ( current_time - rst_fin_rate[ 0 ] ).total_seconds() / len( rst_fin_rate ) )

                if current_rate > avg_rate + alert_multiplier * std_dev:
                    alert( "RST/FIN Flood Detected", pkt[ IP ].src, f"High rate of RST/FIN packets detected: { current_rate:.2f } pps" )
