from scapy.all import DHCP, BOOTP, IP
from alerter.alert import alert
import datetime

module_info = {

    "Author" : "Hossam Ehab",
    "Info"   : "This module detects DHCP spoofing attacks by monitoring DHCP offers and tracking IP addresses offered to clients. \
               It alerts if a client receives offers from different IPs in a short period, indicating potential spoofing.",
    "Title": "DHCP Spoofing Detection Module",
    "Date": "18 MAR 2024",  
    "Category": "Network Security",
    "Description": "Detects DHCP spoofing by monitoring for suspicious DHCP offers. If a client's offered IP changes or if multiple \
                    offers are observed in a short timeframe, an alert is generated to indicate potential spoofing or suspicious network activity.",
    "References": [
        "https://www.sans.org/reading-room/whitepapers/dhcp/understanding-preventing-dhcp-abuse-dhcp-snooping-36267",
        "https://www.cisco.com/c/en/us/support/docs/security-vpn/dynamic-multipoint-vpn-dmvpn/116131-technote-dhcp-00.html"  
    ]

}

dhcp_clients = {}

def detect_dhcp_spoofing( pkt ):

    if pkt.haslayer( DHCP ):
        
        if pkt [ DHCP ].options[ 0 ][ 1 ] == 2:

            client_mac = pkt[ BOOTP ].chaddr.hex(":")
            client_ip = pkt[BOOTP].ciaddr
            src_ip = pkt[IP].src
            
            if client_mac in dhcp_clients:
                if dhcp_clients[client_mac]["ip"] != client_ip:
                    alert("DHCP Spoofing", src_ip, f"Detected DHCP spoofing for client MAC {client_mac}. "
                                                    f"Offered IP address: {client_ip}, "
                                                    f"Previous IP address: {dhcp_clients[client_mac]['ip']}")
            else:
                dhcp_clients[client_mac] = {"ip": client_ip, "timestamps": [datetime.datetime.now()]}
                
            timestamps = dhcp_clients[client_mac]["timestamps"]
            timestamps.append(datetime.datetime.now())
            
            time_diffs = [( timestamps[ i ] - timestamps[ i - 1 ]).total_seconds() for i in range( 1, len(timestamps) )]
            
            if any( time_diff < 60 for time_diff in time_diffs ):
                
                alert("Suspicious Activity", src_ip, f"Suspicious activity detected for client MAC {client_mac}. "
                                                       f"Multiple IP addresses observed within a short timeframe.")
