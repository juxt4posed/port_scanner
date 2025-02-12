#!/bin/python3

from datetime import datetime as dt
import sys
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def set_higher_port():
    global higher_port
    higher_port = input("Please set the highest port you want to scan: ")
    if higher_port.isdigit():
        higher_port = int(higher_port)
        if higher_port > 65535:
            print(f"{higher_port} is higher than 65535, please choose a port between 1-65535")
            set_higher_port()
        elif higher_port < lower_port:
            print(f"{higher_port} is less than your lower limit, please choose a port between {lower_port} and 65535")
            set_higher_port()
    else:
        print("\nSorry, we only accept integers, please try again!\n")
        set_higher_port()

def set_lower_port():
    global lower_port
    lower_port = input("Please set the lowest port you want to scan: ")
    if lower_port.isdigit():
        lower_port = int(lower_port)
        if lower_port < 1:
            print(f"{lower_port} is less than 1, please choose a port between 1 and 65535")
            set_lower_port()
        elif lower_port > 65535:
            print(f"{lower_port} is higher than 65535, please choose a port between 1-65535")
            set_lower_port()
    else:
        print("\nUnfortunately, we only accept integers, please try again!\n")
        set_lower_port()

def get_service_version(port):
    try:
        service_name = socket.getservbyport(port)
        return service_name
    except OSError:
        return "Unknown service"

def scan_port(target, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # opens the socket at port
    socket.setdefaulttimeout(1)  # sets the default timeout
    result = s.connect_ex((target, port))  # returns an error indicator
    s.close()
    if result == 0:
        return port, get_service_version(port)
    return None

def print_progress(current, total):
    percent = (current / total) * 100
    bar_length = 50  # Length of the progress bar
    filled_length = int(bar_length * percent // 100)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    print(f'\r|{bar}| {percent:.2f}% Complete', end='')

def main():
    global lower_port
    global higher_port

    # Check the correct amount of arguments were supplied
    if len(sys.argv) == 2:
        target = socket.gethostbyname(sys.argv[1])
    else:
        print("Invalid amount of arguments")
        print("Syntax: ./portscanner.py (hostname)")
        sys.exit()  # exits the program

    lower_port = 1  # set arbitrary values for the port range
    higher_port = 2

    # Add a pretty banner
    print("-" * 50)
    print("Scanning target: " + target)
    print("-" * 50)
    set_lower_port()
    set_higher_port()
    start_time = dt.now()
    print("-" * 50)
    print("\nTime Started: " + str(start_time))
    print("\n" + "-" * 50)

    total_ports = higher_port - lower_port + 1
    open_ports = []

    # Using ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in range(lower_port, higher_port + 1)}

        for index, future in enumerate(as_completed(futures)):
            result = future.result()
            if result:
                port, service_version = result
                open_ports.append((port, service_version))
                print(f"\nPort {port} is open! Service: {service_version}")
            
            # Update progress
            print_progress(index + 1, total_ports)

    print("\n\nScan complete\n")
    end_time = dt.now()
    total_time = end_time - start_time
    print("The scan took: " + str(total_time.total_seconds()) + " seconds to complete")
    if open_ports:
        print("\nOpen ports found:")
        for port, service in open_ports:
            print(f"Port {port}: {service}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting program")
        sys.exit()
    except socket.gaierror:
        print("\nCouldn't resolve host name")
        sys.exit()
    except socket.error:
        print("\nCouldn't connect to server")
        sys.exit()
