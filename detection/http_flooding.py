from scapy.all import sniff, IP, TCP, Raw
from alerter.alert import alert
from collections import defaultdict, deque
import datetime
import re

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module monitors for HTTP flood attacks by analyzing HTTP request patterns.",
    "Title": "HTTP Flood Detection Module",
    "Date": "19 MAY 2024",
    "Category": "Network Security",
    "Description": "Detects HTTP flood attacks by monitoring for an unusually high number of HTTP requests from a single IP address within a short period.",
    "References": [
        "https://en.wikipedia.org/wiki/Denial-of-service_attack#HTTP_flood",
        "https://owasp.org/www-community/attacks/HTTP_Flood_Attack"
    ]

}

http_request_history = defaultdict( lambda: deque( maxlen = 100 ) )
request_window = 60  # time window in seconds

def parse_http_request( payload ):
    try:
        request = payload.decode( "utf-8" )
        lines = request.split( "\r\n" )
        if lines[ 0 ].startswith( "GET" ) or lines[ 0 ].startswith( "POST" ):
            method, url, _ = lines[ 0 ].split( " " )
            headers = { key: value for ( key, value ) in [ line.split( ": ", 1 ) for line in lines[ 1: ] if ": " in line ] }
            return method, url, headers.get( "User-Agent", "" )
    except Exception as e:
        return None, None, None
    return None, None, None

def detect_http_flood( pkt ):
    if IP in pkt and TCP in pkt and pkt[ TCP ].dport == 80 and Raw in pkt:
        src_ip = pkt[ IP ].src
        current_time = datetime.datetime.now()
        payload = pkt[ Raw ].load

        method, url, user_agent = parse_http_request( payload )
        if method and url:
            http_request_history[ src_ip ].append( ( current_time, url, user_agent ) )
            request_times = [ req[ 0 ] for req in http_request_history[ src_ip ] ]
            unique_urls = len( set( [ req[ 1 ] for req in http_request_history[ src_ip ] ] ) )
            unique_user_agents = len( set( [ req[ 2 ] for req in http_request_history[ src_ip ] ] ) )
            
            # Check the number of requests in the defined window
            if len( request_times ) > 10:  # Threshold of 10 requests
                window_start = request_times[ 0 ]
                if ( current_time - window_start ).total_seconds() < request_window:
                    alert( "HTTP Flood Detected", src_ip, f"High frequency of HTTP requests detected: { len( request_times ) } requests in { request_window } seconds." )
                    http_request_history[ src_ip ].clear()
            
            # Check for multiple requests to unique URLs
            if unique_urls > 10:  # Threshold of 10 unique URLs
                alert( "HTTP Flood Detected", src_ip, f"Multiple unique URL requests detected: { unique_urls } unique URLs." )
                http_request_history[ src_ip ].clear()
            
            # Check for the same User-Agent across many requests
            if unique_user_agents < 2 and len( http_request_history[ src_ip ] ) > 10:  # Same User-Agent in more than 10 requests
                alert( "HTTP Flood Detected", src_ip, f"Multiple requests with the same User-Agent detected: { user_agent }." )
                http_request_history[ src_ip ].clear()

