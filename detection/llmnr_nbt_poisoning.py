from scapy.all import sniff, IP, UDP
from scapy.layers.dns import DNSQR
from alerter.alert import alert
from collections import defaultdict
import datetime

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects LLMNR and NBT-NS poisoning attacks by monitoring for suspicious LLMNR and NBT-NS responses.",
    "Title": "LLMNR/NBT-NS Poisoning Detection Module",
    "Date": "17 MAY 2024",
    "Category": "Network Security",
    "Description": "Detects LLMNR and NBT-NS poisoning attacks by monitoring for suspicious responses to LLMNR and NBT-NS queries.",
    "References": [
        "https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution",
        "https://attack.mitre.org/techniques/T1557/001/"
    ]

}

llmnr_responses = defaultdict( list )
nbt_ns_responses = defaultdict( list )

def detect_llmnr_nbt_ns_poisoning( pkt ):

    if IP in pkt and UDP in pkt:

        src_ip = pkt[ IP ].src
        dst_ip = pkt[ IP ].dst
        udp_dport = pkt[ UDP ].dport

        if udp_dport == 5355 and pkt.haslayer( DNSQR ):  # LLMNR
            
            llmnr_responses[ dst_ip ].append( src_ip )
            if len(set(llmnr_responses[ dst_ip ])) > 1:
                alert("LLMNR Poisoning Detected", dst_ip, f"Multiple responses for LLMNR query detected: {llmnr_responses[ dst_ip ]}")
                llmnr_responses[ dst_ip ] = []

        elif udp_dport == 137 and pkt.haslayer( DNSQR ):  # NBT-NS
            
            nbt_ns_responses[ dst_ip ].append( src_ip )
            if len(set(nbt_ns_responses[ dst_ip ])) > 1:
                alert("NBT-NS Poisoning Detected", dst_ip, f"Multiple responses for NBT-NS query detected: {nbt_ns_responses[dst_ip]}")
                nbt_ns_responses[ dst_ip ] = []
