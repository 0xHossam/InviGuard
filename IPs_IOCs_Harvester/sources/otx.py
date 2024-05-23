import requests
import socket
from urllib.parse import urlparse

class OTX_Siphon( object ):
    def __init__( self, api_key=None ):

        self.otx_api_key = api_key
        self.otx_url = 'https://otx.alienvault.com/'

    def execute( self ):

        ip_addresses = set()
        for pulse in self.get_pulse_generator():
            for indicator in pulse['indicators']:

                if indicator[ 'type' ] in [ 'IPv4', 'IPv6' ]:
                    ip_addresses.add( indicator[ 'indicator' ] )
                elif indicator[ 'type' ] in [ 'domain', 'hostname', 'URL' ]:
                    self.resolve_and_add( indicator[ 'indicator' ], ip_addresses )
        
        return ip_addresses

    def otx_get( self, url ):

        headers = {'X-OTX-API-KEY': self.otx_api_key}
        response = requests.get( url, headers=headers )
        response.raise_for_status()
        return response.json()

    def get_pulse_generator( self ):
 
        args = ['limit=10', 'page=1']
        request_args = '?' + '&'.join(args)
        response_data = self.otx_get(f'{self.otx_url}/api/v1/pulses/subscribed{ request_args }')
        yield from response_data.get('results', [])

    def resolve_and_add( self, indicator_value, ip_addresses ):

        try:

            if indicator_value.startswith('http'):
                parsed_url = urlparse( indicator_value )
                hostname = parsed_url.hostname
            else:

                hostname = indicator_value
            if hostname:
                ip = socket.gethostbyname( hostname )
                ip_addresses.add( ip )

        except Exception as e:
            # print(f"Error resolving { hostname }: { e }")
            pass
