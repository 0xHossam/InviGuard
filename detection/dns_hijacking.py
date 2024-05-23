from scapy.all import DNS, DNSRR
from alerter.alert import alert
import datetime
from collections import defaultdict

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects DNS hijacking by monitoring DNS responses.",
    "Title": "DNS Hijacking Detection Module",
    "Date": "18 MAR 2024",
    "Category": "Network Security",
    "Description": "The module detects DNS hijacking by identifying multiple IP addresses for the same domain.",
    "References": [
        "https://en.wikipedia.org/wiki/DNS_hijacking",
        "https://en.wikipedia.org/wiki/Man-in-the-middle_attack",
    ]

}

dns_history = defaultdict( lambda: { "ips": set(), "timestamps": [] } )

def detect_dns_hijacking( pkt ):

    if pkt.haslayer( DNS ) and pkt.haslayer( DNSRR ):
        query_name = pkt[ DNS ].qd.qname.decode( 'utf-8' )
        response_ip = pkt[ DNSRR ].rdata
        current_time = datetime.datetime.now()

        dns_entry = dns_history[ query_name ]
        dns_entry[ "ips" ].add( response_ip )
        dns_entry[ "timestamps" ].append( current_time )

        # checking for multiple IPs for the same domain
        if len( dns_entry[ "ips" ] ) > 1:
            alert_details = f"Multiple IPs detected for domain { query_name }: {', '.join( dns_entry[ 'ips' ] )}"
            alert( "DNS Hijacking Detected", query_name, alert_details )

        # checking for rapid changes in IP addresses
        if len( dns_entry[ "timestamps" ] ) > 1:
            time_diffs = [ ( dns_entry[ "timestamps" ][ i ] - dns_entry[ "timestamps" ][ i - 1 ] ).total_seconds() for i in range( 1, len( dns_entry[ "timestamps" ] ) ) ]
            if any( diff < 60 for diff in time_diffs ):
                alert_details = f"Rapid IP changes detected for domain { query_name }: {', '.join( dns_entry[ 'ips' ] )}"
                alert( "DNS Hijacking Detected", query_name, alert_details )
