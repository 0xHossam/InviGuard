import datetime
from scapy.all import sniff, Ether, Raw
from collections import defaultdict
from alerter.alert import alert

module_info = {
    "author": "Hossam Ehab",
    "info": "This module detects LLDP spoofing by monitoring LLDP packets and checking for inconsistencies in device information.",
    "title": "LLDP Spoofing Detection Module",
    "date": "2 Jun 2024",
    "category": "Network Security",
    "description": "The module is designed to detect LLDP spoofing activities within network traffic. By monitoring LLDP packets, "
                   "the module identifies potential security threats based on changes in device information such as MAC addresses, "
                   "device names, and port IDs. This helps in early detection of man-in-the-middle attacks and network misconfigurations.",
    "references": [
        "https://tools.ietf.org/html/rfc2922",
        "https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol",
    ]
}

# LLDP history tracker
lldp_history = defaultdict( lambda: {
    "device_names": set( ), 
    "port_ids": set( ), 
    "macs": set( ), 
    "last_update": None, 
    "timestamps": [ ]
} )

class TLV:
    def __init__( self, tlv_type, value ):
        self.tlv_type = tlv_type
        self.value = value

class LLDPDU:
    def __init__( self, data ):
        self.tlvlist = self.parse_tlv( data )

    def parse_tlv( self, data ):
        tlvs = [ ]
        while data:
            tlv_type_length = int.from_bytes( data[ : 2 ], byteorder = 'big' )
            tlv_type = ( tlv_type_length >> 9 ) & 0x7F
            tlv_length = tlv_type_length & 0x01FF
            tlv_value = data[ 2 : 2 + tlv_length ]
            tlvs.append( TLV( tlv_type, tlv_value ) )
            data = data[ 2 + tlv_length: ]
        return tlvs

def detect_lldp_spoofing( pkt ):
    if Ether in pkt and pkt[ Ether ].type == 0x88cc:  # LLDP Ethertype
        src_mac = pkt[ Ether ].src
        lldp_data = LLDPDU( pkt[ Raw ].load )
        device_name = None
        port_id = None
        
        for tlv in lldp_data.tlvlist:
            if tlv.tlv_type == 5:  # assuming 5 is the type for chassis ID (device name)
                device_name = tlv.value.decode( 'utf-8', errors = 'ignore' )
            elif tlv.tlv_type == 7:  # assuming 7 is the type for port ID
                port_id = tlv.value.decode( 'utf-8', errors = 'ignore' )

        if device_name is None or port_id is None:
            return  # cannot proceed without device name or port ID

        lldp_entry = lldp_history[ src_mac ]
        current_time = datetime.datetime.now( )

        # update LLDP history
        lldp_entry[ "last_update" ] = current_time
        lldp_entry[ "timestamps" ].append( current_time )

        # detect new or unexpected device information
        if device_name not in lldp_entry[ "device_names" ]:
            if lldp_entry[ "device_names" ]:
                alert( "LLDP Spoofing Detected", src_mac, f"Unexpected device name: { device_name }. Previous names: { ', '.join( lldp_entry['device_names'] ) }" )
            lldp_entry[ "device_names" ].add( device_name )

        if port_id not in lldp_entry[ "port_ids" ]:
            if lldp_entry[ "port_ids" ]:
                alert( "LLDP Spoofing Detected", src_mac, f"Unexpected port ID: { port_id }. Previous IDs: { ', '.join( lldp_entry['port_ids'] ) }" )
            lldp_entry[ "port_ids" ].add( port_id )

        if src_mac not in lldp_entry[ "macs" ]:
            if lldp_entry[ "macs" ]:
                alert( "LLDP Spoofing Detected", src_mac, f"Unexpected MAC address: { src_mac }. Previous MACs: { ', '.join( lldp_entry['macs'] ) }" )
            lldp_entry[ "macs" ].add( src_mac )

        # detect frequent LLDP packets
        if len( lldp_entry[ "timestamps" ] ) > 1:
            time_diffs = [ lldp_entry[ "timestamps" ][ i ] - lldp_entry[ "timestamps" ][ i - 1 ] for i in range( 1, len( lldp_entry[ "timestamps" ] ) ) ]
            unusual_frequency = any( diff.total_seconds( ) < 10 for diff in time_diffs )  # adjust the threshold as needed

            if unusual_frequency:
                alert( "Unusual LLDP Packet Frequency", src_mac, "Possible LLDP spoofing due to frequent LLDP packets." )

        # detect multiple sources for the same device
        if len( lldp_entry[ "macs" ] ) > 1:
            alert( "Multiple MACs Detected", src_mac, f"Multiple MAC addresses ( { ', '.join( lldp_entry['macs'] ) } ) detected for the same LLDP frame." )
        
        if len( lldp_entry[ "macs" ] ) > 5:
            alert( "Potential LLDP Cache Poisoning", src_mac, f"Multiple MAC addresses ( { ', '.join( lldp_entry['macs'] ) } ) detected for the same LLDP frame. Possible LLDP cache poisoning." )
