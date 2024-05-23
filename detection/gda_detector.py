import math
from scapy.all import DNS, IP, sniff
from alerter.alert import alert
from configs.config_loader import load_config

config = load_config()
dga_detection_config = config.get( 'dga_detection', {} )
MAX_SUBDOMAIN_LENGTH = dga_detection_config.get( 'max_subdomain_length', 20 )
MIN_ENTROPY = dga_detection_config.get( 'min_entropy', 3.5 )  

module_info = {
    "Author": "Hossam Ehab",
    "Info": "This module detects domains generated by Domain Generation Algorithms (DGA) by analyzing the entropy of domain names extracted from DNS queries. Higher entropy is indicative of potential DGA activity, which is commonly used by malware to evade detection and maintain command and control communications.",
    "Title": "DGA Domain Detection Module",
    "Date": "19 MAR 2024",
    "Category": "Network Security",
    "Description": "The DGA Domain Detection Module is designed to enhance cybersecurity defenses by identifying potential DGA-generated domains within network traffic. Utilizing entropy calculations, the module provides real-time alerts for domains that exhibit characteristics typical of those generated by DGAs. This proactive detection is crucial for mitigating the risks associated with malware communications and ensuring network integrity.",
    "References": [
        "https://www.ietf.org/rfc/rfc1035.txt",  # RFC 1035 - Domain Names - Implementation and Specification
        "https://www.sans.org/reading-room/whitepapers/dns/detect",
        "https://www.researchgate.net/publication/265637545_Analyzing_Domain_Generation_Algorithms-based_Malware"  # Research on analyzing DGA-based Malware
    ]
}

def calculate_entropy( domain ):

    if '.' in domain:
        domain = domain.split('.')[ 0 ]  # considering only the subdomain part

    # calculating frequency of each character

    probs = [ float ( domain.count ( c ) ) / len ( domain ) for c in dict.fromkeys ( list ( domain ) ) ]
    # calculating the entropy
    entropy = -sum( [ p * math.log ( p ) / math.log ( 2.0 ) for p in probs ] )
    return entropy

def detect_dga_domains( pkt ):
    if pkt.haslayer( DNS ) and pkt.haslayer( IP ) and pkt[ DNS ].qd is not None:
        domain = pkt[ DNS ].qd.qname.decode( 'utf-8' ).rstrip( '.' )
        src_ip = pkt[ IP ].src

        # checking for the high entropy which may indicate a DGA domain
        entropy = calculate_entropy( domain )
        if entropy > MIN_ENTROPY:
            alert("High Entropy DGA Domain Detected", src_ip, f"High entropy ({ entropy:.2f }) detected in domain: { domain }")
            return True
        return False

