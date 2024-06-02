import datetime
from scapy.all import Ether, LLDPDU, sniff
from collections import defaultdict
from alerter.alert import alert

# module metadata
module_info = {

    "author": "Hossam Ehab",
    "info": "this module detects lldp spoofing by monitoring lldp packets and checking for inconsistencies in device information.",
    "title": "lldp spoofing detection module",
    "date": "2 jun 2024",
    "category": "network security",
    "description": "the module is designed to detect lldp spoofing activities within network traffic. by monitoring lldp packets, "
                   "the module identifies potential security threats based on changes in device information such as mac addresses, "
                   "device names, and port ids. this helps in early detection of man-in-the-middle attacks and network misconfigurations.",
    "references": [
        "https://tools.ietf.org/html/rfc2922",
        "https://en.wikipedia.org/wiki/link_layer_discovery_protocol",
    ]

}

# lldp history tracker
lldp_history = defaultdict( lambda: {
    "device_names": set(), 
    "port_ids": set(), 
    "macs": set(), 
    "last_update": None, 
    "timestamps": []
})

def detect_lldp_spoofing( pkt ):
    
    if pkt.haslayer( LLDPDU ):
        src_mac = pkt[ Ether ].src
        device_name = pkt[ LLDPDU ].tlvlist[ 0 ].value  # assuming the first tlv is the device name
        port_id = pkt[ LLDPDU ].tlvlist[ 1 ].value      # assuming the second tlv is the port id
        lldp_entry = lldp_history[ src_mac ]
        current_time = datetime.datetime.now()

        # update lldp history
        lldp_entry[ "last_update" ] = current_time
        lldp_entry[ "timestamps" ].append( current_time )

        # detect new or unexpected device information
        if device_name not in lldp_entry[ "device_names" ]:
            if lldp_entry[ "device_names" ]:
                alert( "lldp spoofing detected", src_mac, f"unexpected device name: { device_name }. previous names: { ', '.join( lldp_entry['device_names'] ) }" )
            lldp_entry[ "device_names" ].add( device_name )

        if port_id not in lldp_entry[ "port_ids" ]:
            if lldp_entry[ "port_ids" ]:
                alert( "lldp spoofing detected", src_mac, f"unexpected port id: { port_id }. previous ids: { ', '.join( lldp_entry['port_ids'] ) }" )
            lldp_entry[ "port_ids" ].add( port_id )

        if src_mac not in lldp_entry[ "macs" ]:
            if lldp_entry[ "macs" ]:
                alert( "lldp spoofing detected", src_mac, f"unexpected mac address: { src_mac }. previous macs: { ', '.join( lldp_entry['macs'] ) }" )
            lldp_entry[ "macs" ].add( src_mac )

        # detect frequent lldp packets
        if len( lldp_entry[ "timestamps" ] ) > 1:
            time_diffs = [ lldp_entry[ "timestamps" ][ i ] - lldp_entry[ "timestamps" ][ i - 1 ] for i in range( 1, len( lldp_entry[ "timestamps" ] ) )]
            unusual_frequency = any( diff.total_seconds() < 10 for diff in time_diffs )  # adjust the threshold as needed

            if unusual_frequency:
                alert( "unusual lldp packet frequency", src_mac, "possible lldp spoofing due to frequent lldp packets." )

        # detect multiple sources for the same device
        if len( lldp_entry[ "macs" ] ) > 1:
            alert( "multiple macs detected", src_mac, f"multiple mac addresses ({ ', '.join( lldp_entry['macs'] ) }) detected for the same lldp frame." )
        
        if len( lldp_entry[ "macs" ] ) > 5:
            alert( "potential lldp cache poisoning", src_mac, f"multiple mac addresses ({ ', '.join( lldp_entry['macs'] ) }) detected for the same lldp frame. possible lldp cache poisoning." )
