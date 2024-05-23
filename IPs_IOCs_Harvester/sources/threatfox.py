import requests
import json
import socket
from urllib.parse import urlparse

class ThreatFoxAPI:

    def __init__( self, api_key ):

        self.base_url = 'https://threatfox-api.abuse.ch/api/v1/'
        self.headers = { 'Content-Type': 'application/json', 'API-KEY': api_key }

    def query_recent_iocs( self, days=3 ):

        data = { 'query': 'get_iocs', 'days': days }
        response = requests.post( self.base_url, data=json.dumps( data ), headers=self.headers )
        
        if response.status_code == 200:
            return response.json()['data']
        else:
            print("Error:", response.text)

    def extract_ips( self, iocs ):

        for ioc in iocs:

            ioc_type = ioc.get('ioc_type', '')
            ioc_value = ioc.get('ioc', '')

            if ioc_type in ['ipv4', 'ipv6']:
                print( ioc_value )
            elif ioc_type in ['hostname', 'domain']:
                
                try:
                    ip = socket.gethostbyname( ioc_value )
                    print( ip )
                except socket.gaierror as e:
                    # print(f"Failed to resolve {ioc_value} to IP: {str(e)}")
                    continue

            elif ioc_type == 'url':

                parsed_url = urlparse( ioc_value )
                if parsed_url.hostname:

                    try:
                        ip = socket.gethostbyname( parsed_url.hostname )
                        print( ip )
                    except socket.gaierror as e:
                        # print(f"Failed to resolve { parsed_url.hostname } to IP: {str( e )}")
                        pass
