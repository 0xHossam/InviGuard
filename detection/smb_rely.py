from scapy.all import sniff, IP, TCP
from impacket.smb import SMB
from impacket.smbconnection import SessionError
from alerter.alert import alert
from collections import defaultdict
import datetime

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module monitors for SMB relay attacks by analyzing SMB traffic patterns and detecting unusual authentication sequences.",
    "Title": "SMB Relay Attack Detection Module",
    "Date": "15 MAY 2024",
    "Category": "Network Security",
    "Description": "Detects SMB relay attacks by monitoring for unusual authentication sequences and patterns indicative of credential relay activities.",
    "References": [
        "https://en.wikipedia.org/wiki/SMB_protocol",
        "https://attack.mitre.org/techniques/T1171/",
        "https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smb-troubleshooting-tools"
    ]

}

smb_history = defaultdict(
    lambda: {
        "auth_attempts": [],
        "last_update": None,
        "session_ids": set(),
        "suspicious_activity": 0
    }
)

def detect_smb_relay(pkt):
    if IP in pkt and TCP in pkt and pkt[TCP].dport == 445:
        try:
            smb = SMB(pkt[IP].src, pkt[IP].dst)
            smb_session_setup_andx = smb.SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
            
            src_ip = pkt[IP].src
            current_time = datetime.datetime.now()
            smb_entry = smb_history[src_ip]

            # Track unique session IDs to identify potential relays
            session_id = smb_session_setup_andx['SessionID']
            smb_entry["session_ids"].add(session_id)
            smb_entry["auth_attempts"].append(current_time)
            smb_entry["last_update"] = current_time

            # Checking for unusual frequency of authentication attempts
            if len(smb_entry["auth_attempts"]) > 1:
                time_diffs = [smb_entry["auth_attempts"][i] - smb_entry["auth_attempts"][i - 1] for i in range(1, len(smb_entry["auth_attempts"]))]
                unusual_frequency = any(diff.total_seconds() < 10 for diff in time_diffs)

                if unusual_frequency:
                    alert("Unusual SMB Authentication Frequency", src_ip, "Possible SMB relay attack due to frequent authentication attempts.")

            # Checking for multiple authentication attempts from the same IP
            if len(smb_entry["auth_attempts"]) > 5:
                alert("Multiple SMB Authentication Attempts", src_ip, "Multiple SMB authentication attempts detected, indicating a potential SMB relay attack.")

            # Detect if there are multiple unique session IDs within a short timeframe
            if len(smb_entry["session_ids"]) > 3:
                alert("Multiple SMB Session IDs", src_ip, f"Multiple session IDs detected from {src_ip}, indicating a possible SMB relay attack.")

            smb_entry["suspicious_activity"] += 1
            if smb_entry["suspicious_activity"] > 10:
                alert("High Suspicious Activity", src_ip, "High volume of suspicious activity detected, indicating a potential SMB relay attack.")
                smb_entry["suspicious_activity"] = 0
        
        except SessionError as e:
            print(f"SMB Session Error: {e}")
