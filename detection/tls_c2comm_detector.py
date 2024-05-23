from scapy.all import load_layer
from alerter.alert import alert
from scapy.all import IP

# load_layer("tls") # cuz is is already loaded

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module leverages Scapy to inspect packets for TLS layers and compares detected certificates \
             against a predefined list of indicators associated with known malicious C2 frameworks. Alerts are generated \
             for any match found, indicating potential malicious communication or compromise.",
    "Title": "C2 TLS Certificate Detection Module",
    "Date": "21 MAR 2024",
    "Category": "Network Security",
    "Description": "By examining TLS traffic, this module identifies potential command and control (C2) communications \
                    based on known TLS certificate attributes. It supports a wide range of C2 frameworks, including but not limited to \
                    Cobalt Strike, Metasploit Framework, and Emotet. Detection is based on specific certificate characteristics \
                    known to be used by these frameworks for secure communication with compromised hosts.",
    "References": [
        "https://www.scapy.net",  # Scapy: Packet manipulation program & library
        "https://attack.mitre.org/tactics/TA0011/",  # MITRE ATT&CK: Command And Control
        "https://www.exploit-db.com/",  # The Exploit Database
    ]

}
def detect_known_c2_tls_certificates( pkt ):
    
    if pkt.haslayer('TLS'):
    
        TLS = pkt.getlayer('TLS')
        src_ip = pkt[ IP ].src
        tls_bytes = bytes( TLS )

        for c2_framework, values in malicious_tls_values.items():
            
            for value in values:
                if value.encode() in tls_bytes:
                    details = f"Potential C2 communication using indicator {value}"
                    alert( c2_framework, src_ip, details )
                    return  # exit after the first match to avoid multiple alerts for the same packet


malicious_tls_values = {
    "Cobalt Strike": [
        "146473198"
    ],
    "Metasploit Framework": [
        "MetasploitSelfSignedCA"
    ],
    "Covenant": [
        "Covenant"
    ],
    "Mythic": [
        "Mythic"
    ],
    "PoshC2": [
        "P18055077"
    ],
    "Sliver": [
        "multiplayer+operators"
    ]
}