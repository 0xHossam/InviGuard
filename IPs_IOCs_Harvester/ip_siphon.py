module_info = {

    "Author": "Hossam Ehab",
    "Info": "This script consolidates threat intelligence from diverse sources including OTX, URLHaus, \
             AbuseIPDB, TweetFeed, and ThreatFox. It extracts IPs associated with threats, compiling \
             them into a unified list.",
    "Title": "Threat Intelligence Aggregation Script",
    "Date": "18 MAR 2024",
    "Category": "Threat Intelligence",
    "Description": "Automating the collection of threat data, this script harnesses APIs of various threat intelligence \
                    services. It updates a centralized list of IPs with new entries, aiding in the continuous \
                    enrichment of security mechanisms.",
    "References": [
        "https://otx.alienvault.com/api",  # AlienVault OTX API Documentation
        "https://urlhaus.abuse.ch/api/",  # URLhaus API Documentation
        "https://www.abuseipdb.com/",  # AbuseIPDB API Documentation
        "https://www.threatfox.io/",  # ThreatFox API Documentation
        "https://www.tweetfeed.live/", # Tweetfeed API Documentation
    ]

}

from .sources.otx import OTX_Siphon
from .sources.urlhaus import URLHaus_Siphon
from .sources.abuseipdb import AbuseIPDB_Siphon
from .sources.tweetfeed import TweetFeedAPI 
from .sources.threatfox import ThreatFoxAPI 

from configs.config_loader import load_config

def get_ips():

    config = load_config()

    OTXAPIKey = config['api_keys']['OTXAPIKey']
    abuseipdbAPIKey = config['api_keys']['AbuseIPDBAPIKey']
    threatfox_api_key = config['api_keys']['ThreatFoxAPIKey']

    # otx alien vault
    otx_siphon = OTX_Siphon( api_key = OTXAPIKey )
    ips_otx = otx_siphon.execute() or []

    # urlhaus
    urlhaus_siphon = URLHaus_Siphon()
    ips_urlhaus = urlhaus_siphon.execute() or []

    # abuseipdb
    abuseipdb_siphon = AbuseIPDB_Siphon( api_key = abuseipdbAPIKey )
    ips_abuseipdb = abuseipdb_siphon.execute() or []

    # tweetfeed
    tweetfeed_siphon = TweetFeedAPI()  
    ips_tweetfeed = tweetfeed_siphon.execute() or []  

    # threatfox
    threatfox_api = ThreatFoxAPI( api_key = threatfox_api_key )
    recent_iocs = threatfox_api.query_recent_iocs( days = 7 )
    ips_threatfox = threatfox_api.extract_ips( recent_iocs ) or []

    all_ips = set().union( ips_otx, ips_urlhaus, ips_abuseipdb, ips_tweetfeed, ips_threatfox )
    return all_ips

def update_ip_file( ip_filename = "..\\data\\ip.txt" ):

    existing_ips = set()
    
    try:
        with open( ip_filename, 'r' ) as file:
            existing_ips = set( file.read().splitlines() )
    
    except FileNotFoundError:
        print(f"[!] { ip_filename } not found. It will be created.")

    new_ips = set(get_ips()) - existing_ips

    if new_ips:
        with open( ip_filename, 'a' ) as file:
            for ip in new_ips:
                file.write(ip + '\n')
        print(f"IP addresses have been updated in { ip_filename }.")
    else:
        print("No new IP addresses to update.")

if __name__ == "__main__":
    update_ip_file()
