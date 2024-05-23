from scapy.all import IP, TCP, Raw, sniff
from alerter.alert import alert
import datetime

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module inspects HTTP headers for unusual or malicious patterns that might indicate C2 communication. It checks for unusual User-Agent strings and other header anomalies.",
    "Title": "HTTP Header Analysis Module",
    "Date": "24 MAR 2024",
    "Category": "Network Security",
    "Description": "The HTTP Header Analysis Module provides security by inspecting HTTP headers for anomalies that could indicate malicious activity. It analyzes User-Agent strings, hostnames, and other HTTP header fields for unusual patterns, flagging potential C2 communication attempts. This module helps in identifying and mitigating threats by closely monitoring HTTP traffic.",
    "References": [
        "https://tools.ietf.org/html/rfc2616",  # Hypertext Transfer Protocol -- HTTP/1.1
        "https://www.owasp.org/index.php/OWASP_HTTP_Post_Tool",  # OWASP HTTP Post Tool
    ]

}

suspicious_user_agents = [
    "curl", "wget", "python-requests", "libwww-perl", "Scrapy", "Java", "Go-http-client", "MauiBot", 
    "sqlmap", "nikto", "masscan", "Nmap", "nmap"
]

suspicious_tlds = [".xyz", ".top", ".club", ".gq", ".ru", ".cn"]

def analyze_http_headers( pkt ):

    if pkt.haslayer( IP ) and pkt.haslayer( TCP ) and pkt.haslayer( Raw ):
        try:
            payload = pkt[ Raw ].load.decode( 'utf-8', errors='ignore' )
            if "HTTP" in payload:
                headers = payload.split( "\r\n" )
                user_agent = ""
                host = ""
                unusual_headers = []
                
                for header in headers:
                    if "User-Agent" in header:
                        user_agent = header.split( ": " )[ 1 ]
                    elif "Host" in header:
                        host = header.split( ": " )[ 1 ]
                    else:
                        if header and ":" in header:
                            header_key, header_value = header.split( ": ", 1 )
                            if len( header_value ) > 500 or any( char in header_value for char in [ '%', '<', '>', '{', '}', '|', '^', '~', '[', ']', '`' ] ):
                                unusual_headers.append( header )
                
                if user_agent:
                    if any( ua in user_agent for ua in suspicious_user_agents ):
                        alert( "Suspicious User-Agent Detected", pkt[ IP ].src, f"Unusual User-Agent string: { user_agent }" )
                    elif len( user_agent ) < 10 or any( char in user_agent for char in [ '%', '<', '>', '{', '}', '|', '^', '~', '[', ']', '`' ] ):
                        alert( "Malicious User-Agent Detected", pkt[ IP ].src, f"Potentially malicious User-Agent string: { user_agent }" )
                
                if host:
                    if any( host.endswith( tld ) for tld in suspicious_tlds ):
                        alert( "Suspicious Hostname Detected", pkt[ IP ].src, f"Unusual hostname: { host }" )
                    elif any( char in host for char in [ '%', '<', '>', '{', '}', '|', '^', '~', '[', ']', '`' ] ):
                        alert( "Malicious Hostname Detected", pkt[ IP ].src, f"Potentially malicious hostname: { host }" )

                if unusual_headers:
                    for header in unusual_headers:
                        alert( "Unusual HTTP Header Detected", pkt[ IP ].src, f"Suspicious HTTP header: { header }" )

        except Exception as e:
            print( f"Error processing packet: { e }" )
