#!/bin/python3
##import required modules
from datetime import datetime as dt
import sys
import socket
import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed

#func to resolve URL to IP
def resolve_target(target):
    """Resolve a domain name to an IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: Unable to resolve {target} to an IP address.")
        sys.exit(1)

#func attempts to send header to get the service name of an open port
def get_service_version(port, protocol):
    """Get the service name for a given port and protocol."""
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "Unknown service"

#TCP multi-threaded scan
def scan_tcp(target, port):
    """Scans a TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1) # 1 second timeout in case a port doesnt respond
        result = s.connect_ex((target, port))
        if result == 0:
            service = get_service_version(port, "tcp")
            return f"Port {port}/TCP is open | Service: {service}"
    return None

async def scan_udp(target, port):
    """Scans a UDP port asynchronously with service-specific payloads for better accuracy."""
    udp_payloads = {
        53: b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01',  # DNS Query
        123: b'\x1b' + 47 * b'\0',  # NTP Request
        161: b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04p\x86\x99s\x02\x01\x00\x02\x01\x00\x30\x0b\x30\t\x06\x05+\x06\x01\x02\x01\x05\x00',  # SNMP
        69: b'\x00\x01\x00\x01\x00\x01\x00\x00\x00\x00\x00\x01',  # TFTP RRQ
        67: b'\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DHCP Discover
        1812: b'\x01\x03\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # RADIUS Access Request
    }
    
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(), remote_addr=(target, port))
    try:
        payload = udp_payloads.get(port, b'\x00')  # Use known payload or default to null byte
        transport.sendto(payload)
        await asyncio.sleep(0.5)
        transport.close()
        service = get_service_version(port, "udp")
        return f"Port {port}/UDP is open | Service: {service}"
    except Exception:
        transport.close()
        return None

def print_progress(current, total):
    """Display a progress bar."""
    percent = (current / total) * 100
    bar_length = 50
    filled_length = int(bar_length * percent // 100)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    print(f'\r|{bar}| {percent:.2f}% Complete', end='', flush=True)

async def main():
    max_concurrent_udp_scans = 50  # Limit concurrent UDP scans
    semaphore = asyncio.Semaphore(max_concurrent_udp_scans)

    print("Welcome to the Advanced Port Scanner!")
    target = input("Enter target domain or IP address: ")
    target = resolve_target(target)
    lower_port = int(input("Enter lower port range: "))
    upper_port = int(input("Enter upper port range: "))
    scan_type = input("Enter scan type (tcp, udp, both): ").strip().lower()
    if scan_type not in ["tcp", "udp", "both"]:
        print("Invalid scan type. Defaulting to TCP.")
        scan_type = "tcp"
    
    print("-" * 50)
    print(f"Scanning target: {target} ({scan_type.upper()})")
    print("-" * 50)
    start_time = dt.now()

    total_ports = upper_port - lower_port + 1
    open_ports = []

    tasks = []
    with ThreadPoolExecutor(max_workers=1000) as executor:
        tcp_futures = []
        
        for port in range(lower_port, upper_port + 1):
            if scan_type in ["tcp", "both"]:
                future = executor.submit(scan_tcp, target, port)
                tcp_futures.append(future)

            if scan_type in ["udp", "both"]:
                tasks.append(scan_udp(target, port))

        # Process TCP results as they complete
        for index, future in enumerate(as_completed(tcp_futures)):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"\n{result}")
            print_progress(index + 1, total_ports)

    # Process UDP results asynchronously as they complete
    for index, coro in enumerate(asyncio.as_completed(tasks)):
        result = await coro
        if result:
            open_ports.append(result)
            print(f"\n{result}")
        print_progress(index + 1 + len(tcp_futures), total_ports)

    print("\n\nScan complete.")
    end_time = dt.now()
    print(f"Time taken: {end_time - start_time}")

    if open_ports:
        print("\nOpen ports found:")
        for port_info in open_ports:
            print(port_info)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(1)
    except socket.gaierror:
        print("\nCouldn't resolve hostname.")
        sys.exit(1)
    except socket.error:
        print("\nCouldn't connect to target.")
        sys.exit(1)