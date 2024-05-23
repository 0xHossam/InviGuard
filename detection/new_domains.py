from scapy.all import DNS, IP
from alerter.alert import alert
import whois
from datetime import datetime

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects communication with newly registered domains by analyzing DNS queries. It checks the registration date of domains and raises an alert if the domain was registered recently, which is a common tactic used by malicious actors for C2 communication.",
    "Title": "Newly Registered Domain Detection Module",
    "Date": "20 MAR 2024",
    "Category": "Network Security",
    "Description": "The Newly Registered Domain Detection Module is designed to enhance network security by identifying DNS queries to newly registered domains. Such domains are often used in malicious activities, including C2 communications. This module checks the registration date of domains in real-time and alerts if the domain is newly registered, allowing for early detection and response to potential threats.",
    "References": [
        "https://www.icann.org/resources/pages/gtld-registration-data-specs-en",  # ICANN gTLD Registration Data Specification
        "https://www.sans.org/reading-room/whitepapers/dns/detecting-c2-domains-37840",  # Detecting C2 Domains using DNS
        "https://securitytrails.com/blog/understanding-dns",  # Understanding DNS and its security implications
    ]

}

def is_newly_registered( domain ):

    try:
        domain_info = whois.whois( domain )
        creation_date = domain_info.creation_date
        if isinstance( creation_date, list ):
            creation_date = creation_date[ 0 ]
        if creation_date:
            current_date = datetime.now()
            age = ( current_date - creation_date ).days
            if age < 30:  # threshold for "newly registered"
                return True
    except Exception as e:
        print( f"Error checking domain registration date: { e }" )
    return False

def detect_newly_registered_domains( pkt ):

    if pkt.haslayer( DNS ) and pkt.haslayer( IP ) and pkt[ DNS ].qd is not None:
        domain = pkt[ DNS ].qd.qname.decode( 'utf-8' ).rstrip( '.' )
        src_ip = pkt[ IP ].src

        if is_newly_registered( domain ):
            alert( "Newly Registered Domain Detected", src_ip, f"Domain { domain } was registered recently wich is can be indicator." )
            return True
        return False
