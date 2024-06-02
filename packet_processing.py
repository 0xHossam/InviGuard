from detection.arp_spoofing import detect_arp_spoofing
from detection.dos_ddos import detect_dos_ddos
from detection.dns_spoofing import detect_dns_spoofing
from detection.dhcp_spoofing import detect_dhcp_spoofing
from detection.mitm import detect_mitm
from detection.portscan_detect import detect_port_scan
from detection.ports_monitor import start_port_monitoring
from detection.geolocation_detector import geo_analyze_packet
from detection.tls_c2comm_detector import detect_known_c2_tls_certificates
from detection.gda_detector import detect_dga_domains
from detection.flow_analyzer import update_flow
from detection.smb_rely import detect_smb_relay
from detection.dns_tunneling import detect_dns_tunneling
from detection.icmp_tunneling import detect_icmp_tunneling
from detection.ip_spoofing import detect_ip_spoofing
from detection.llmnr_nbt_poisoning import detect_llmnr_nbt_ns_poisoning
from detection.p2p_c2_comm import detect_p2p_c2_communication
from detection.mac_spoofing import detect_mac_spoofing
from detection.ip_null_scan import detect_ip_null_scan
from detection.rst_fin_flood import detect_rst_fin_flood
from detection.mac_flooding import detect_mac_flooding
from detection.doh import detect_doh
from detection.http_beaconing import detect_http_beaconing
from detection.http_headers_analysis import analyze_http_headers
from detection.new_domains import detect_newly_registered_domains
from detection.tor_exit_nodes import detect_tor_traffic
from detection.dns_hijacking import detect_dns_hijacking
from detection.lldp_spoofing import detect_lldp_spoofing
from alerter.alert import alert

from scapy.all import IP, ICMP, TCP, UDP, ARP, DNS
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.network_utils import resolve_port_name, format_timestamp
from utils.config import read_malicious_ips
from colorama import Fore, Style

import logging, socket, collections, threading

logging.basicConfig( filename = '../logging/packets.log', level = logging.INFO, format = '%(asctime)s - %(levelname)s - %(message)s' )

malicious_ips = read_malicious_ips()
local_ip = socket.gethostbyname( socket.gethostname() )
traffic_rate = {}
dns_cache = {}

def process_packet( pkt ):
    global malicious_ips

    # port monitoring in a separate thread
    # port_monitoring_thread = threading.Thread( target = start_port_monitoring )
    # port_monitoring_thread.start()

    def execute_detection_task( func , lock , *args ):
        try:
            with lock:
                func( *args )
        except Exception as e:
            logging.error(f"Error in detection task { func.__name__ }: {str( e )}")

    detection_tasks = [

        ( detect_arp_spoofing , pkt ),
        ( detect_dos_ddos , pkt ),
        ( detect_dns_spoofing , pkt ),
        ( detect_dhcp_spoofing , pkt ),
        ( detect_mitm , pkt ),
        ( detect_port_scan , pkt ),
        # ( geo_analyze_packet , pkt ),
        ( detect_known_c2_tls_certificates , pkt ),
        ( detect_dga_domains , pkt ),
        ( update_flow , pkt ),
        ( detect_smb_relay , pkt ),
        ( detect_dns_tunneling , pkt ),
        ( detect_ip_spoofing , pkt ),
        ( detect_p2p_c2_communication , pkt ),
        ( detect_llmnr_nbt_ns_poisoning , pkt ),
        ( detect_mac_spoofing , pkt ),
        ( detect_mac_flooding , pkt),
        ( detect_ip_null_scan , pkt ),
        ( detect_rst_fin_flood , pkt ),
        ( detect_doh , pkt ),
        ( detect_http_beaconing , pkt ),
        ( analyze_http_headers , pkt ),
        ( detect_newly_registered_domains , pkt ),
        ( detect_tor_traffic , pkt ),
        ( detect_icmp_tunneling , pkt ),
        ( detect_dns_hijacking , pkt ),
        ( detect_lldp_spoofing , pkt )

    ]

    num_workers = min( len ( detection_tasks ) , 150 )
    lock = threading.Lock()
    with ThreadPoolExecutor( max_workers = num_workers ) as executor:
        futures = [ executor.submit ( execute_detection_task, task[ 0 ], lock, *task[ 1: ] ) for task in detection_tasks ]
        for future in as_completed( futures ):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error in detection task: {str ( e ) }")


    timestamp = format_timestamp()
    src_mac = pkt.src
    dst_mac = pkt.dst
    protocol = "Unknown"
    extra_details = []

    if IP in pkt:
        src_ip = pkt[ IP ].src
        dst_ip = pkt[ IP ].dst

        direction = "OUT" if src_ip == local_ip else "IN"
        protocol = "IP"

        extra_details.extend([
            f"src_ip={ src_ip }",
            f"dst_ip={ dst_ip }",
            f"direction={ direction }",
            f"ttl={ pkt[ IP ].ttl }",
            f"length={ pkt[ IP ].len }"
        ])

        if src_ip in malicious_ips or dst_ip in malicious_ips:
            alert_type = "Malicious Source IP Detected" if src_ip in malicious_ips else "Malicious Destination IP Detected"
            alert( alert_type, src_ip if src_ip in malicious_ips else dst_ip, f"{ protocol } packet with malicious IP detected." )

        if ICMP in pkt:
            protocol = "ICMP"
            extra_details.append( f"type={ pkt[ ICMP ].type }" )
            extra_details.append( f"code={ pkt[ ICMP ].code }" )

        elif TCP in pkt:
            protocol = "TCP"
            extra_details.append( f"src_port={ pkt[ TCP ].sport } ( { resolve_port_name( pkt[ TCP ].sport, 'tcp' ) } ) " )
            extra_details.append( f"dst_port={ pkt[ TCP ].dport } ( { resolve_port_name( pkt[ TCP ].dport, 'tcp' ) } ) " )
            flags = pkt[ TCP ].flags
            extra_details.append( f"flags={ flags }" )

        elif UDP in pkt:
            protocol = "UDP"
            extra_details.append( f"src_port={ pkt[ UDP ].sport } ( { resolve_port_name( pkt[ UDP ].sport, 'udp' ) } ) " )
            extra_details.append( f"dst_port={ pkt[ UDP ].dport } ( { resolve_port_name( pkt[ UDP ].dport, 'udp' ) } ) " ) 

        if DNS in pkt:
            protocol = "DNS"
            dns_layer = pkt[ DNS ]
            extra_details.append( f"transaction_id={ dns_layer.id } " )
            dns_type = "Query" if dns_layer.qr == 0 else "Response"
            extra_details.append( f"query_type={ dns_type }" )

            if dns_layer.qr == 0 and dns_layer.qd is not None:  # DNS query
                queried_domain = dns_layer.qd.qname.decode()
                extra_details.append( f"queried_domain={ queried_domain }" )
            elif dns_layer.qr == 1:  # DNS response
                if dns_layer.ancount > 0:
                    answers = ', '.join( [ dns_layer.an[ i ].rrname.decode() for i in range( min( dns_layer.ancount, 5 ) ) ] )
                    extra_details.append( f"answers={ answers }" )

    elif ARP in pkt:
        protocol = "ARP"
        operation = "Request" if pkt[ ARP ].op == 1 else "Reply"
        src_ip = pkt[ ARP ].psrc
        dst_ip = pkt[ ARP ].pdst
        extra_details.append( f"operation={ operation }" )
        extra_details.append( f"src_ip={ src_ip }" )
        extra_details.append( f"dst_ip={ dst_ip }" )
    
    extra_details_str = ", ".join( extra_details )
    log_message = f"{ timestamp }, { src_mac }, { dst_mac }, { protocol }, { extra_details_str }"
    
    print( f" { Fore.YELLOW } [-] { log_message } { Style.RESET_ALL }" )
    # logging.info( log_message )
