from scapy.all import IP, sniff
from alerter.alert import alert
import requests

module_info = {
    "Author": "Hossam Ehab",
    "Info": "This module analyzes the geo-location of IP addresses in network traffic. It identifies communication with IP addresses from unusual or suspicious locations.",
    "Title": "Geo-Location Analysis & Detection Module",
    "Date": "25 MAR 2024",
    "Category": "Network Security",
    "Description": "The Geo-Location Analysis & Detection Module enhances security by analyzing the geographic location of IP addresses involved in network communication. It identifies connections to and from IP addresses located in unusual or high-risk regions, flagging them for further investigation. This module helps in detecting and mitigating threats by considering the geo-location of network traffic.",
    "References": [
        "https://www.ietf.org/rfc/rfc7942.txt",  # IETF Geographic Location/Privacy (geopriv)
        "https://www.sans.org/reading-room/whitepapers/networkdevs/detecting-blocking-geo-location-aware-attacks-35392",  # Detecting and Blocking Geo-Location Aware Attacks
    ]
}

def get_geo_location( ip ):
    try:
        response = requests.get( f"https://geolocation-db.com/json/{ ip }&position=true" )
        data = response.json()
        return data
    except Exception as e:
        print( f"Error fetching geo-location data: { e }" )
        return None

def detect_geo_location_anomalies( pkt ):
    if pkt.haslayer( IP ):
        src_ip = pkt[ IP ].src
        dst_ip = pkt[ IP ].dst

        src_location = get_geo_location( src_ip )
        dst_location = get_geo_location( dst_ip )

        if src_location and dst_location:
            if src_location['country_code'] != 'US' or dst_location['country_code'] != 'US':
                alert( "Suspicious Geo-Location Detected", src_ip, f"Communication with IP located in { src_location['country_name'] } to { dst_location['country_name'] }" )
