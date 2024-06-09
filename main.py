from scapy.all import sniff
from packet_processing import process_packet
from IPs_IOCs_Harvester.ip_siphon import update_ip_file
import argparse, threading, time
import psutil
import socket
from colorama import init, Fore, Style
from utils.banner import banner, under_banner

init( autoreset = True )

def list_interfaces():
    
    interfaces = psutil.net_if_addrs()
    interface_list = [ iface for iface in interfaces.keys() ]
    return interface_list

def get_interface_name():

    interfaces = list_interfaces()
    if not interfaces:
        print(f"{ Fore.RED }No network interfaces found.")
        return None

    print(f"{ Fore.CYAN }[+] Available network interfaces : \n")
    for i, iface in enumerate( interfaces ):
        print(f"\t{i}: { Fore.YELLOW }{ iface }")

    while True:
        try:
            iface_index = int( input( f"\n{ Fore.GREEN }[*] Select the interface number to monitor on > "))
            if 0 <= iface_index < len( interfaces ):
                return interfaces[ iface_index ]
            else:
                print(f"{Fore.RED}Invalid interface number. Please try again.")
        except ValueError:
            print(f"{Fore.RED}Invalid input. Please enter a number.")

def sniff_packets( filter ):

    selected_iface = get_interface_name()
    if selected_iface is None:
        print(f"{ Fore.RED }No suitable network interface selected.")
        return

    print(f"{ Fore.MAGENTA }[*] Starting project on interface { Fore.YELLOW }{ selected_iface }{ Fore.MAGENTA }...")
    sniff( filter=filter, prn=process_packet, store=0, iface=selected_iface )

def periodically_update_ips():

    while True:
        print(f"{ Fore.BLUE }[*] Updating IP addresses list ...")
        update_ip_file("../data/ip.txt")
        time.sleep( 3600 )  # IOCs updated every hour / 3600 seconds

def main():

    print( Fore.GREEN + banner + Style.RESET_ALL )
    print( Fore.RED + under_banner + Style.RESET_ALL )
    
    parser = argparse.ArgumentParser(description='HIDS Network Monitoring Tool')
    parser.add_argument('--filter', '-f', type=str, default="", help='BPF filter for specific protocols. Default is empty, sniffing all traffic.')
    args = parser.parse_args()

    update_ips = input(f"{ Fore.GREEN }[+] Do you want to periodically update the IOCs in background ? (yes/no):").strip().lower()

    if update_ips == 'yes':
        update_thread = threading.Thread( target=periodically_update_ips, daemon=True )
        update_thread.start()

    sniff_packets( args.filter )

if __name__ == '__main__':
    main()
    print(f"{ Fore.GREEN }[+] Let's play man!")
