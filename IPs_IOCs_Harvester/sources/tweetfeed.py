import requests
import socket

class TweetFeedAPI:
    
    def __init__(self):
        self.base_url = "https://api.tweetfeed.live/v1/"
    
    def get_iocs(self, time, filter1=None, filter2=None):
        
        endpoint = f"{ self.base_url }{ time }"
        if filter1:
            endpoint += f"/{ filter1 }"
        if filter2:
            endpoint += f"/{ filter2 }"
        
        try:

            response = requests.get( endpoint )
            response.raise_for_status()
            return response.json()
        
        except requests.exceptions.RequestException:
            return []

    def resolve_hostname( self, hostname ):
        
        try:
            return socket.gethostbyname( hostname )
        except socket.gaierror:
            return None

    def execute( self ):

        resolved_ips = set()
        for ioc_type in [ "url", "domain" ]:
            iocs = self.get_iocs( "today", ioc_type )
            for ioc in iocs:
                hostname = ioc[ 'value' ]

                if ioc_type == "url":
                    hostname = hostname.split("//") [ -1 ].split("/") [ 0 ]
                ip_address = self.resolve_hostname( hostname )

                if ip_address:
                    resolved_ips.add( ip_address )
        return resolved_ips
