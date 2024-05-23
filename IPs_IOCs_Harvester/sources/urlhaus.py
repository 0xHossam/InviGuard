import requests
import socket
from urllib.parse import urlparse

class URLHaus_Siphon( object ):
    def __init__(self):
        self.urlhaus_url = 'https://urlhaus-api.abuse.ch/v1/urls/recent/'

    def execute( self ):
        ip_addresses = set()
        response = requests.get( self.urlhaus_url )
        if response.status_code == 200:
            for entry in response.json()['urls']:
                self.resolve_and_add(entry['url'], ip_addresses)
        return ip_addresses

    def resolve_and_add( self, url, ip_addresses ):
        try:
            parsed_url = urlparse(url)
            if parsed_url.hostname:
                ip = socket.gethostbyname(parsed_url.hostname)
                ip_addresses.add(ip)
        except Exception as e:
            # print(f"Error resolving {parsed_url.hostname}: {e}")
            pass