import psutil
import asyncio
from alerter.alert import alert

module_info = {

    "author": "Hossam Ehab",
    "info": "this module utilizes psutil to continuously monitor the system for changes in open network ports, \
             alerting in real-time when ports are opened or closed.",
    "title": "real-time port monitoring module",
    "date": "21 mar 2024",
    "category": "system monitoring",
    "description": "a proactive network monitoring solution, this module tracks open and closed ports on a system, \
                    issuing alerts for any changes. it ensures comprehensive surveillance of the system's network interfaces.",
    "references": [
        "https://psutil.readthedocs.io/en/latest/",  # psutil documentation
        "https://docs.python.org/3/library/asyncio.html",  # Python asyncio documentation
        "https://owasp.org/www-community/controls/Unused_and_unnecessary_services",  # OWASP: Unused and unnecessary services
    ]

}

async def get_open_ports():
    open_ports = set()
    for conn in psutil.net_connections( kind='inet' ):
        if conn.status == 'LISTEN':
            open_ports.add( conn.laddr.port )
    return open_ports

async def monitor( interval = 30 ):
    last_ports = await get_open_ports()
    while True:
        current_ports = await get_open_ports()
        opened_ports = current_ports - last_ports
        closed_ports = last_ports - current_ports

        for port in opened_ports:
            alert("port opened", "localhost", f"port {port} is now open")

        for port in closed_ports:
            alert("port closed", "localhost", f"port {port} has been closed")

        last_ports = current_ports
        await asyncio.sleep(interval)

async def start_port_monitoring():
    num_instances = 2  # running 2 instances in parallel

    tasks = [monitor(30) for _ in range(num_instances)]
    await asyncio.gather(*tasks)

