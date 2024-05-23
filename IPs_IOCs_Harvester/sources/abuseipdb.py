import requests

class AbuseIPDB_Siphon( object ):

    def __init__( self, api_key ):

        self.api_key = api_key
        self.url = 'https://api.abuseipdb.com/api/v2/blacklist'
        
        self.headers = {
            'Accept': 'text/plain',
            'Key': self.api_key
        }
        
        self.params = {
            'confidenceMinimum': '90'
        }

    def execute( self ):
        
        ip_addresses = set()
        response = requests.get( self.url, headers=self.headers, params=self.params )
        response.raise_for_status()
        ip_addresses.update( response.text.strip().split('\n') )
        
        return ip_addresses
