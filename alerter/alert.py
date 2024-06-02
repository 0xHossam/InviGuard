from alerter.formatter import FormatterFactory
from threading import Lock
import logging
from winotify import Notification, audio
from ui.app import add_alert  

import requests  # in alert.py

def send_alert_to_flask(alert_data):
    url = 'http://localhost:5000/api/add_alert'
    requests.post(url, json=alert_data)


logging.basicConfig(filename='warning.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

alert_counts = {}
alert_counts_lock = Lock()
output_formats = ['CSV', 'JSON', 'PDF']  

descriptions = {

    "DNS Hijacking Detected": "DNS hijacking involves intercepting and redirecting DNS queries to malicious servers, allowing attackers to redirect traffic to malicious websites. This alert indicates that multiple IP addresses have been detected for the same domain, suggesting potential DNS hijacking.",
    "Rapid IP Changes Detected": "Rapid changes in IP addresses associated with a single domain can indicate DNS hijacking or other malicious activities. This alert is triggered when IP addresses for a domain change frequently within a short period.",
    "Malicious User-Agent Detected": "A user-agent string that is known to be associated with malicious activity or automated tools has been detected in network traffic, suggesting potential use of unauthorized or harmful applications.",
    "Malicious Hostname Detected": "A hostname in network traffic that is known for suspicious or harmful activities has been detected, warranting further investigation for potential threats.",
    "Unusual HTTP Header Detected": "An HTTP header that deviates from the norm has been detected in network traffic, potentially indicating an attempt to exploit vulnerabilities, bypass security controls, or perform reconnaissance.",
    "Frequent IP Changes Detected": "Frequent changes in IP addresses associated with a single MAC address can indicate suspicious activity, such as IP spoofing or attempts to evade detection by frequently changing IPs.",
    "MAC Spoofing Detected": "MAC spoofing involves changing the MAC address of a network device to disguise its identity, often used to bypass security controls or impersonate another device on the network.",
    "ARP Spoofing Detected": "ARP spoofing involves sending fake ARP messages over a local area network. This technique exploits the lack of authentication in the ARP protocol to link an attacker's MAC address with the IP address of a legitimate computer or server on the network.",
    "Unusual ARP Response Frequency": "An unusually high frequency of ARP responses may indicate an ongoing ARP spoofing attack, where an attacker attempts to intercept, modify, or stop data in transit.",
    "Multiple MACs Detected": "Detecting multiple MAC addresses for the same IP could indicate ARP cache poisoning, a technique used to attack a network by associating the attacker’s MAC address with the IP address of a legitimate computer or server.",
    "Potential ARP Cache Poisoning": "This alert indicates possible ARP cache poisoning, where multiple MAC addresses are associated with a single IP, potentially redirecting traffic to an attacker.",
    "DHCP Spoofing": "DHCP spoofing occurs when an attacker sends fake DHCP responses to clients, assigning them an IP address controlled by the attacker. This can lead to man-in-the-middle attacks or network disruption.",
    "Suspicious Activity": "This general alert indicates suspicious network activity that may not fit a specific attack pattern but warrants further investigation.",
    "DNS Spoofing": "DNS spoofing, or DNS cache poisoning, involves introducing corrupt DNS cache information to redirect traffic to malicious sites, facilitating phishing attacks or spreading malware.",
    "DNS Tunneling": "DNS tunneling involves encoding the data of other programs or protocols in DNS queries and responses. It can be used for malicious purposes, including data exfiltration.",
    "DDoS Attack": "A Distributed Denial of Service (DDoS) attack aims to overwhelm a targeted server, service, or network by flooding it with Internet traffic, rendering it unavailable to users.",
    "DoS Attack": "A Denial of Service (DoS) attack aims to shut down a machine or network, making it inaccessible to its intended users by overwhelming it with traffic.",
    "MITM Detected": "Man-In-The-Middle (MITM) attacks involve an attacker secretly relaying and possibly altering the communication between two parties who believe they are directly communicating with each other.",
    "Port Scanning Detected": "Port scanning is a method used by attackers to discover vulnerable services that they can potentially exploit on a networked computer.",
    "Malicious Destination IP Detected": "The system has identified a connection attempt to an IP address that is known for suspicious activities, as listed in our threat intelligence database from IOCs Feeds Platform.",
    "Malicious Source IP Detected": "A network connection was initiated from an IP address recognized for harmful activities, as listed in our threat intelligence database from IOCs Feeds Platform.",
    "Frequent DNS Queries": "A high number of DNS queries in a short period may suggest suspicious activity, such as DNS tunneling or data exfiltration.",
    "High Traffic Anomaly": "A significant increase in network traffic could indicate a potential attack, such as a DDoS, or a misconfigured network device.",
    "High Entropy DGA Domain Detected": "A domain generated by a Domain Generation Algorithm (DGA) has been detected, often used by malware to evade detection by frequently changing its domain names.",
    "HTTP Flood Detected": "An HTTP flood attack aims to overwhelm a server with HTTP requests, causing a denial of service to legitimate users.",
    "ICMP Tunneling Detected": "ICMP tunneling is a method of using ICMP packets to covertly transmit data, potentially indicating data exfiltration or covert communication channels.",
    "Frequent ICMP Packets": "An unusual number of ICMP packets could indicate network scanning or ICMP tunneling, which is often used for reconnaissance or covert communication.",
    "Unusual SMB Authentication Frequency": "A high frequency of SMB authentication attempts may suggest a brute force attack, where an attacker is attempting to guess passwords to gain access to a network.",
    "Multiple SMB Authentication Attempts": "Multiple failed SMB authentication attempts could indicate a brute force attack, where an attacker is trying to gain unauthorized access by guessing passwords.",
    "Multiple SMB Session IDs": "Multiple SMB session IDs from a single IP may indicate suspicious activity, such as an attempt to evade detection by using multiple sessions.",
    "Possible TLS MITM Detected": "Potential man-in-the-middle activity detected on a TLS connection, which could compromise the confidentiality and integrity of the encrypted communication.",
    "LLMNR Poisoning Detected": "Link-Local Multicast Name Resolution (LLMNR) poisoning is an attack where an attacker responds to LLMNR requests intended for other hosts, potentially redirecting traffic to malicious sites.",
    "NBT-NS Poisoning Detected": "NetBIOS Name Service (NBT-NS) poisoning is similar to LLMNR poisoning, where an attacker responds to NBT-NS requests, potentially redirecting traffic to malicious sites.",
    "IP Spoofing Detected": "IP spoofing involves sending packets with a false source IP address, potentially used to bypass IP-based authentication or to disguise the origin of an attack.",
    "P2P Communication Detected": "Peer-to-peer (P2P) communication detected on the network, which could be used for legitimate purposes or for malicious activities such as file sharing of illegal content.",
    "MAC Flooding Detected": "MAC flooding involves sending numerous packets to a switch, each with a different source MAC address, potentially causing the switch to enter a fail-open mode and broadcast traffic to all ports.",
    "Frequent MAC Changes Detected": "Frequent changes in MAC addresses on a network interface may indicate spoofing or a scanning tool, potentially used to evade detection or to perform reconnaissance.",
    "IP Null Scan Detected": "An IP Null scan is a type of network scan where the attacker sends packets with no TCP flags set, potentially used to identify open ports by observing the target's response.",
    "RST/FIN Flood Detected": "RST/FIN flooding involves sending a large number of TCP RST or FIN packets to a target, potentially disrupting legitimate TCP connections or exhausting resources.",
    "Possible DNS over HTTPS (DoH) Detected": "This detection indicates potential use of DNS over HTTPS (DoH), which could be used to bypass traditional DNS monitoring mechanisms and obscure DNS queries from security tools.",
    "HTTP/S Beaconing Detected": "HTTP/S beaconing involves periodic communication between a compromised device and a command and control server, often indicating malware activity and the presence of an advanced persistent threat.",
    "Tor Exit Node Traffic Detected": "Traffic to or from known Tor exit nodes has been detected, which may indicate anonymized communication often associated with malicious activity, such as browsing the dark web or bypassing censorship.",
    "Newly Registered Domain Detected": "A connection to a domain that was recently registered has been detected, which can be indicative of phishing or command-and-control (C2) domains used by attackers to evade detection.",
    "Suspicious User-Agent Detected": "A user-agent string that is uncommon or known to be associated with malicious activity has been detected in network traffic, potentially indicating the use of automated tools or malware.",
    "Suspicious Hostname Detected": "A hostname in network traffic that appears unusual or is associated with known threats has been detected, warranting further investigation for potential malicious activity.",
    "Suspicious Geo-Location Detected": "Network traffic originating from or destined to an unusual or high-risk geographic location has been detected, suggesting potential malicious activity or policy violations.",
    "LLDP Spoofing Detected": "LLDP spoofing involves sending fake LLDP packets to mislead network devices about the network topology, potentially leading to man-in-the-middle attacks and network misconfigurations. This alert indicates detection of unexpected device information, frequent LLDP packets, or multiple MAC addresses for the same device, suggesting potential LLDP spoofing.",

}



def alert(alert_type, src_ip, details):

    global alert_counts
    alert_key = (alert_type, src_ip)
    attack_description = descriptions.get(alert_type, "No description available for this alert type.")
    alert_data = {
        "alert_type": alert_type,
        "src_ip": src_ip,
        "details": details,
        "description": attack_description,
        "count": None
    }

    with alert_counts_lock:
        alert_counts[alert_key] = alert_counts.get(alert_key, 0) + 1
        alert_data["count"] = alert_counts[alert_key]

        send_alert_to_flask(alert_data)

        if alert_data["count"] <= 3:
            message = f"[Detected attack ( { alert_type } )] Source IP: { src_ip }, Details: { details }, Description: { attack_description }"
            print(f"\033[91m{message}\033[0m")

            for format_type in output_formats:
                formatter = FormatterFactory.get_formatter( format_type )
                formatter.format(alert_data)
                logging.info(f"Alert saved in { format_type } format with description.")
            
            # Creating a toast notification with the attack description
            toast = Notification(app_id="Alert System",
                                 title="Security Alert - " + alert_type,
                                 msg=f"Detected from { src_ip }. { attack_description }",
                                 duration="long")  
            
            toast.set_audio(audio.Default, loop=False)
            toast.show()

