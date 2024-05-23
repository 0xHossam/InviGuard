import re
import ssl
import urllib.request

def fetch_data( url ):

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(url, context=ctx) as response:
            data = response.read().decode('utf-8')
        return data
    except Exception as e:
        # print(f"Error fetching data from {url}: {e}")
        return None

def extract_ips( data ):
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', data)
    return ips

def extract_urls( data ):
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', data)
    return urls

def main():
    url_data = fetch_data("http://vxvault.net/URL_List.php")
    if url_data:
        urls = extract_urls( url_data )
        print("Extracted URLs:")
        for url in urls:
            print(url)
    # else:
        # print("Failed to fetch URLs.")

    print("\nExtracted IPs:")
    for i in range( 20 ):
        s = i * 40
        viri_list_url = f"http://vxvault.net/ViriList.php?s={ s }&m=40"
        page_data = fetch_data( viri_list_url )
        if page_data:
            ips = extract_ips( page_data )
            for ip in ips:
                print( ip )

if __name__ == "__main__":
    main()
