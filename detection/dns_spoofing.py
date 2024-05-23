import datetime
from scapy.all import DNS, IP
from utils.config import dns_cache
from alerter.alert import alert
from configs.config_loader import load_config

config = load_config()
suspicious_activity_config = config.get('suspicious_activity', {})

MAX_DOMAIN_LENGTH = suspicious_activity_config.get('max_domain_length', 70)  # the default to 70 if not found
MIN_QUERY_INTERVAL = suspicious_activity_config.get('min_query_interval', 10)
MAX_QUERIES_SHORT_TIMEFRAME = suspicious_activity_config.get('max_queries_short_timeframe', 5)

dns_cache = {}
module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects DNS spoofing and tunneling by analyzing DNS queries and responses. \
             It checks for unusually long domain names, frequent queries to the same domain, and inconsistencies between \
             the source IP of the DNS response and the expected IP address.",
    "Title": "DNS Spoofing and Tunneling Detection Module",
    "Date": "19 MAR 2024",
    "Category": "Network Security",
    "Description": "The module is designed to detect DNS spoofing and DNS tunneling activities within network traffic. \
                    By monitoring DNS queries and responses, the module identifies potential security threats based on \
                    domain name length, query frequency, and IP address discrepancies. This aids in early detection of \
                    malicious activities such as data exfiltration or man-in-the-middle attacks.",
    "References": [
        "https://www.ietf.org/rfc/rfc1035.txt",  # RFC 1035 - Domain Names - Implementation and Specification
        "https://www.sans.org/reading-room/whitepapers/dns/detect"
    ]

}

def detect_dns_spoofing( pkt ):
    if pkt.haslayer( DNS ) and pkt.haslayer( IP ) and pkt[ DNS ].qd is not None:
        domain = pkt[ DNS ].qd.qname.decode('utf-8').rstrip('.')
        src_ip = pkt[ IP ].src
        
        # DNS tunneling detection based on domain name length
        if len( domain ) > MAX_DOMAIN_LENGTH:
            alert("DNS Tunneling", src_ip, f"Detected potential DNS tunneling based on domain length for '{ domain }'.")

        if domain in dns_cache:
            # DNS spoofing detection
            if dns_cache[ domain ][ "ip" ] != src_ip:
                alert("DNS Spoofing", src_ip, f"Detected spoofed DNS response for domain '{ domain }'. "
                                                f"Legitimate IP: { dns_cache[domain]['ip'] }, "
                                                f"Received IP: { src_ip }")
                
            # checking for frequent queries to the same domain
            dns_cache[ domain ]["timestamps"].append(datetime.datetime.now())
            if len( dns_cache[domain]["timestamps"] ) > MAX_QUERIES_SHORT_TIMEFRAME:
                
                # too many queries in a short timeframe might indicate tunneling
                first_query_time = dns_cache[ domain ]["timestamps"][0]
                last_query_time = dns_cache[ domain ]["timestamps"][-1]
                if ( last_query_time - first_query_time ).total_seconds() < MIN_QUERY_INTERVAL:
                    alert("DNS Tunneling", src_ip, f"Detected potential DNS tunneling based on query frequency for '{domain}'.")
                
                dns_cache[ domain ]["timestamps"].pop(0)
        
        else:

            dns_cache[ domain ] = {"ip": src_ip, "timestamps": [datetime.datetime.now()]}

        # DNS spoofing detection for A records in responses
        if pkt[ DNS ].qr == 0 and pkt[ DNS ].ancount > 0:
            for i in range(pkt[DNS].ancount):
                if pkt[DNS].an[i].type == 1:  # A record
                    response_ip = pkt[DNS].an[i].rdata
                    if domain in dns_cache and response_ip != dns_cache[domain]["ip"]:
                        alert("DNS Spoofing", src_ip, f"Detected spoofed DNS response for domain '{domain}'. "
                                                        f"Legitimate IP: {dns_cache[domain]['ip']}, "
                                                        f"Received IP: {response_ip}")
