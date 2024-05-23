import psutil
import time
from concurrent.futures import ThreadPoolExecutor
from alerter.alert import alert

module_info = {

    "Author": "Hossam Ehab",
    "Info": "This module utilizes psutil to continuously monitor the system for changes in open network ports, \
             alerting in real-time when ports are opened or closed.",
    "Title": "Real-Time Port Monitoring Module",
    "Date": "21 MAR 2024",
    "Category": "System Monitoring",
    "Description": "A proactive network monitoring solution, this module tracks open and closed ports on a system, \
                    issuing alerts for any changes. It ensures comprehensive surveillance of the system's network interfaces.",
    "References": [
        "https://psutil.readthedocs.io/en/latest/",  # psutil documentation
        "https://docs.python.org/3/library/concurrent.futures.html",  # Python concurrent.futures documentation
        "https://owasp.org/www-community/controls/Unused_and_unnecessary_services",  # OWASP: Unused and unnecessary services
    ]

}

def get_open_ports():
    open_ports = set()
    for conn in psutil.net_connections( kind='inet' ):
        
        if conn.status == 'LISTEN':
            open_ports.add( conn.laddr.port )
    return open_ports

def monitor( interval = 30 ):
    last_ports = get_open_ports()
    while True:
        current_ports = get_open_ports()
        opened_ports = current_ports - last_ports
        closed_ports = last_ports - current_ports

        for port in opened_ports:
            alert("Port Opened", "localhost", f"Port {port} is now open")

        for port in closed_ports:
            alert("Port Closed", "localhost", f"Port {port} has been closed")

        last_ports = current_ports
        time.sleep(interval)

def start_port_monitoring():
    num_instances = 2  # running 2 instances in parallel

    with ThreadPoolExecutor( max_workers=num_instances ) as executor:
        futures = [executor.submit(monitor, 30) for _ in range(num_instances)]

        # waiting for all submitted tasks to complete (in this case, they won't unless manually stopped)
        for future in futures:
            try:
                future.result()
            except Exception as e:
                # print(f"An error occurred: {e}")
                continue
            
def start_port_monitoring_wrapper():
    try:
        start_port_monitoring()  
    except Exception as exc:
        print(f'start_port_monitoring generated an exception: {exc}')

