from scapy.all import sniff, DNS, IP, UDP
from alerter.alert import alert
from collections import defaultdict
import datetime
import re

def entropy( data ):

    from collections import Counter
    import math
    
    if not data:
        return 0
    
    counter = Counter( data )
    entropy = 0
    
    for count in counter.values():
        p = count / len( data )
        entropy -= p * math.log2( p )
    
    return entropy

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module monitors for DNS tunneling by analyzing DNS query patterns.",
    "Title": "DNS Tunneling Detection Module",
    "Date": "16 MAY 2024",
    "Category": "Network Security",
    "Description": "Detects DNS tunneling by analyzing DNS query patterns for signs of data exfiltration or covert communication.",
    "References": [
        "https://en.wikipedia.org/wiki/DNS_tunneling",
        "https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-36782",
    ]

}

dns_queries = defaultdict( list )

def detect_dns_tunneling( pkt ):

    if pkt.haslayer( DNS ) and pkt[ DNS ].qr == 0:  # DNS query
        dns_layer = pkt.getlayer( DNS )
        query_name = dns_layer.qd.qname.decode()
        src_ip = pkt[ IP ].src
        current_time = datetime.datetime.now()
        
        dns_queries[ src_ip ].append( { "query": query_name, "timestamp": current_time } )
        
        # reduce false positives by filtering out common and known good domains
        known_good_patterns = [
            re.compile(r"^.*\.google\.com$"),
            re.compile(r"^.*\.microsoft\.com$"),
            re.compile(r"^.*\.facebook\.com$"),
            re.compile(r"^.*\.amazon\.com$"),
            re.compile(r"^.*\.netflix\.com$")
        ]

        if any( pattern.match( query_name ) for pattern in known_good_patterns ):
            return

        # checking for unusual length of DNS queries
        if len( query_name ) > 50:
            alert( "DNS Tunneling Detected", src_ip, f"Suspicious DNS query length detected: { query_name }" )

        # checking for high entropy in query names
        if entropy( query_name ) > 4.0:
            alert( "DNS Tunneling Detected", src_ip, f"High entropy in DNS query detected: { query_name }" )

        # checking for frequent DNS queries within a short time frame
        query_times = [ query["timestamp"] for query in dns_queries[ src_ip ] ]
        time_diffs = [ query_times[ i ] - query_times[ i - 1 ] for i in range( 1, len( query_times ) ) ]
        frequent_queries = any( diff.total_seconds() < 2 for diff in time_diffs )

        if frequent_queries:
            alert( "Frequent DNS Queries", src_ip, "Frequent DNS queries detected, indicating potential DNS tunneling." )

