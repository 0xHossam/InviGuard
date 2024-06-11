from configs.config_loader import load_config
from scapy.all import *
import threading, logging, time, os, collections, socket
from threading import Lock
import os

arp_history = defaultdict (
    
    lambda: {
        "macs": [],
        "last_update": None
        
    }
    
)

# logging.basicConfig(filename='warning.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

local_ip = socket.gethostbyname(socket.gethostname())
arp_table = collections.defaultdict(set)
mac_flood_detection = collections.Counter()
mac_seen_times = defaultdict(list)

config = load_config()
thresholds = config['thresholds']
network_detection = config['network_detection']

mac_flood_threshold = thresholds["mac_flood_threshold"] 
ddos_threshold = thresholds['ddos_threshold']  
dos_threshold = thresholds['dos_threshold']    
max_threshold = thresholds['max_threshold']  
post_exfil_threshold = thresholds['post_exfil_threshold']
post_data_threshold = thresholds['post_data_threshold']
post_time_window = thresholds['post_time_window']
smtp_threshold = thresholds['smtp_threshold']
# time_window = thresholds['time_window']

trusted_network_prefixes = network_detection['trusted_network_prefixes']
suspicious_threshold = network_detection['suspicious_threshold']
time_window = network_detection['time_window']
ttl_threshold = network_detection['ttl_threshold']
hijack_rst_threshold = network_detection['hijack_rst_threshold']
hijack_time_window = network_detection['hijack_time_window']



traffic_rate = {}
dns_cache = {}
alert_counts = {}
alert_counts_lock = Lock()

def read_malicious_ips(filename='data/ip.txt'):

    def load_malicious_ips():
        try:
            with open(filename, 'r') as file:
                return {line.strip() for line in file if line.strip()} 
        except FileNotFoundError:
            print(f"File {filename} not found. No IP filters applied.")
            return set()
    
    def watch_file():
        nonlocal malicious_ips
        last_modified = os.stat(filename).st_mtime

        while True:
            time.sleep(2) 
            current_modified = os.stat(filename).st_mtime
            if current_modified != last_modified:
                print(f"[+] Changes detected in {filename}. Reloading malicious IPs...")
                new_ips = load_malicious_ips()
                added_ips = new_ips - malicious_ips
                if added_ips:
                    print(f"[*] New malicious IPs detected: {', '.join(added_ips)}")
                    malicious_ips.update(added_ips)
                last_modified = current_modified

    malicious_ips = load_malicious_ips()
    thread = threading.Thread(target=watch_file)
    thread.daemon = True  
    thread.start()

    return malicious_ips

