#!/bin/python
import pyfiglet
import sys
import socket
import struct
from datetime import datetime

ascii_banner = pyfiglet.figlet_format("Port Scanner With OS Fingerprint")
print(ascii_banner)

# Define TTL values for common operating systems
TTL_VALUES = {
    "Windows": 128,
    "Linux": 64,
    "MacOS": 64,
    # Add more TTL values as needed
}

def get_ttl_os(ttl):
    for os, ttl_value in TTL_VALUES.items():
        if ttl == ttl_value:
            return os
    return "Unknown"

def scan_ports(target, start_port, end_port):
    print(f"Scanning target {target} for open ports with OS fingerprinting...\n")
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Adjust the timeout as needed
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open")
            try:
                # Get TTL value from the received packet
                ttl = struct.unpack("!B", sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1))[0]
                os_guess = get_ttl_os(ttl)
                print(f"    OS guess for port {port}: {os_guess}")
            except Exception as e:
                print(f"    Error getting TTL: {e}")
        sock.close()

def main():
    if len(sys.argv) != 4:
        print("Invalid number of arguments.")
        print("Syntax: Python3 scanner.py <ip> <start_port> <end_port>")
        sys.exit(1)

    target = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    print("-" * 50)
    print("Scanning target " + target)
    print("Time Started: " + str(datetime.now()))
    print("-" * 50)

    scan_ports(target, start_port, end_port)

if __name__ == "__main__":
    main()
