from scapy.all import IP, TCP
from collections import defaultdict
from time import time
from alerter.alert import alert
from utils.config import smtp_threshold, time_window

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects unauthorized SMTP relaying activities by monitoring outgoing email patterns and analyzing SMTP logs. \
             It leverages thresholds for email traffic volume and connection frequency to identify potential misuse of SMTP servers.",
    "Title": "SMTP Relay Detection Module",
    "Date": "11 JUN 2024",
    "Category": "Email Security",
    "Description": "Designed to detect unauthorized SMTP relaying, this module monitors email traffic patterns, analyzing connection frequency \
                    and data volume to identify suspicious activities. Alerts are triggered upon detecting excessive email relaying, \
                    facilitating timely response to potential spam or abuse incidents.",
    "References": [
        "https://sendgrid.com/docs/glossary/smtp-relay/",
        "https://www.tenable.com/plugins/nessus/118017",
        "https://support.mailchannels.com/hc/en-us/articles/115000511091-How-does-MailChannels-Outbound-Filtering-work-"
    ]

}

smtp_stats = defaultdict( lambda: {
    'connections': 0,
    'timestamps': [],
    'ips': set()
} )

SMTP_PORT = 25

def detect_smtp_relay( pkt ):
    if IP in pkt and TCP in pkt and pkt[ TCP ].dport == SMTP_PORT:
        src_ip = pkt[ IP ].src
        stats = smtp_stats[ src_ip ]
        
        stats[ 'connections' ] += 1
        stats[ 'timestamps' ].append( time( ) )
        stats[ 'ips' ].add( src_ip )
        
        # check for suspicious activity
        current_time = time( )
        recent_connections = [ ts for ts in stats[ 'timestamps' ] if current_time - ts < time_window ]
        if len( recent_connections ) > smtp_threshold:
            alert_details = ( f"IP: { src_ip }, Connections: { len( recent_connections ) }, "
                              f"Unique IPs: { len( stats['ips'] ) }" )
            alert( "SMTP Relay Detected", src_ip, alert_details )
            # reset stats
            smtp_stats[ src_ip ] = {
                'connections': 0,
                'timestamps': [],
                'ips': set()
            }
