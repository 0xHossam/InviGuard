from scapy.all import IP, TCP, Raw
from alerter.alert import alert

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module detects the use of DNS over HTTPS (DoH) in network traffic. DoH can be used by malware to bypass traditional DNS monitoring and filtering mechanisms.",
    "Title": "DNS Over HTTPS (DoH) Detection Module",
    "Date": "27 MAR 2024",
    "Category": "Network Security",
    "Description": "The DNS Over HTTPS (DoH) Detection Module identifies network traffic that uses DoH to resolve domain names. By inspecting HTTPS requests for patterns indicative of DNS queries, this module helps in detecting and mitigating attempts to bypass traditional DNS security measures.",
    "References": [
        "https://tools.ietf.org/html/rfc8484",  # DNS Queries over HTTPS (DoH)
        "https://www.sans.org/reading-room/whitepapers/dns/dns-over-https-doh-39889",  # DNS over HTTPS (DoH) - SANS
    ]

}

doh_endpoints = [
    "dns.google.com",  # Google DNS
    "cloudflare-dns.com",  # Cloudflare DNS
    "dns.quad9.net",  # Quad9 DNS
    "dns10.quad9.net",  # Quad9 DNS
    "dns11.quad9.net",  # Quad9 DNS
    "dns12.quad9.net",  # Quad9 DNS
    "doh.opendns.com",  # OpenDNS
    "doh.cleanbrowsing.org",  # CleanBrowsing DNS
    "dns.nextdns.io",  # NextDNS
    "resolver2.dnscrypt.info",  # DNSCrypt
    "doh.securedns.eu",  # SecureDNS
    "basic.rethinkdns.com",  # RethinkDNS
    "doh.crypto.sx",  # CryptoDNS
    "doh-fi.blahdns.com",  # BlahDNS
    "doh-jp.blahdns.com",  # BlahDNS
    "doh-de.blahdns.com",  # BlahDNS
    "jp.tiar.app",  # Tiar DNS
    "fi.tiar.app",  # Tiar DNS
    "doh.tiarap.org",  # Tiar DNS
]

def detect_doh( pkt ):

    if pkt.haslayer( IP ) and pkt.haslayer( TCP ) and pkt.haslayer( Raw ):
        payload = pkt[ Raw ].load.decode( 'utf-8', errors='ignore' )
        if any( endpoint in payload for endpoint in doh_endpoints ):
            alert( "Possible DNS over HTTPS (DoH) Detected", pkt[ IP ].src, f"Traffic to { pkt[ IP ].dst } might be using DoH." )
