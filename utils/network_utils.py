import socket
import datetime

def format_timestamp(): 
    
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def resolve_port_name(port, protocol):

    try:
        return socket.getservbyport( port, protocol )
    except:
        return str( port )

