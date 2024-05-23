from scapy.all import IP, load_layer
from alerter.alert import alert
import datetime
from collections import defaultdict

module_info = {

    "Author": "Hossam Ehab",
    "Info": "Monitors TLS communication to detect potential MITM attacks by analyzing new sessions, TLS alerts, and handshake types.",
    "Title": "SSL/TLS Monitoring and MITM Detection Module",
    "Date": "21 MAR 2024",
    "Category": "Network Security",
    "Description": "Enhances network security by detecting suspicious TLS activities, providing early warnings of potential MITM attacks through session and handshake analysis.",
    "References": [
        "https://www.scapy.net",
        "https://tools.ietf.org/html/rfc5246",
        "https://owasp.org/www-community/attacks/Man-in-the-middle_attack",
    ]

}

# dynamically loading the TLS layer because of a internal library bug in scapy TLS
load_layer("tls")

tls_history = defaultdict(
    lambda: 
        {
            "sessions": set(), 
            "last_update": None
        }
)

def ssl_tls_monitor( pkt ):

    TLS = pkt.getlayer('TLS')
    
    if TLS:  # pkt.haslayer(TLS) 
        src_ip = pkt[ IP ].src
        src_mac = pkt.src
        current_time = datetime.datetime.now()

        tls_session_id = TLS.session_id
        tls_entry = tls_history[src_ip]

        if tls_session_id not in tls_entry["sessions"]:
            tls_entry["sessions"].add(tls_session_id)
            alert_details = f"New TLS session detected for IP {src_ip}: Session ID {tls_session_id.hex()}"
            alert("Possible TLS MITM Detected", src_ip, alert_details)

        tls_entry["last_update"] = current_time

        tls_flags = TLS.flags
        if tls_flags & 0x01:
            alert_level = TLS.payload.alert_level
            alert_description = TLS.payload.alert_description
            alert_details = f"TLS Alert detected from {src_ip}: Level {alert_level}, Description {alert_description}"
            alert("Possible TLS MITM Detected", src_ip, alert_details)
        
        if tls_flags & 0x02:
            handshake_type = TLS.payload.handshake_type
            if handshake_type == 1:
                alert_details = f"TLS Client Hello detected from {src_ip}"
                alert("Possible TLS MITM Detected", src_ip, alert_details)
            elif handshake_type == 2:
                alert_details = f"TLS Server Hello detected from {src_ip}"
                alert("Possible TLS MITM Detected", src_ip, alert_details)
