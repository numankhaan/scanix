#!/bin/python
import pyfiglet
import socket
import struct
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Lock for smooth printing in multithreading
progress_lock = threading.Lock()
current_percent = 0

# Print ASCII banner once
ascii_banner = pyfiglet.figlet_format("Port Scanner With OS Fingerprint")
print(ascii_banner)

# TTL values for common operating systems
TTL_VALUES = {
    "Windows": 128,
    "Linux": 64,
    "MacOS": 64,
}

def get_ttl_os(ttl):
    for os, ttl_value in TTL_VALUES.items():
        if ttl == ttl_value:
            return os
    return "Unknown"

def scan_single_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))

        if result == 0:
            print(f"\n[+] Port {port} is open")
            try:
                ttl = struct.unpack("!B", sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1))[0]
                os_guess = get_ttl_os(ttl)
                print(f"    OS guess: {os_guess}")
            except:
                print("    Could not read TTL")
        sock.close()
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

def scan_ports(target, start_port, end_port):
    print(f"\nScanning target {target} using multi-threaded mode...\n")

    ports = list(range(start_port, end_port + 1))
    total_ports = len(ports)
    scanned_count = 0
    next_percent = 10

    def wrapped_scan(port):
        nonlocal scanned_count, next_percent
        scan_single_port(target, port)
        scanned_count += 1
        percent_done = int((scanned_count / total_ports) * 100)
        if percent_done >= next_percent:
            with progress_lock:
                print(f"Scanning... {next_percent}%")
            next_percent += 10

    with ThreadPoolExecutor(max_workers=100) as executor:
        tasks = [executor.submit(wrapped_scan, port) for port in ports]
        for _ in as_completed(tasks):
            pass

def main():
    while True:
        print("\n--- Port Scanner Menu ---")
        print("1. Start a new scan")
        print("2. Exit")
        choice = input("Enter your choice (1-2): ").strip()

        if choice == "1":
            target = input("Enter target IP or hostname: ").strip()
            start_port = int(input("Enter start port: ").strip())
            end_port = int(input("Enter end port: ").strip())

            print("-" * 50)
            print(f"Scanning target {target}")
            print("Time Started: " + str(datetime.now()))
            print("-" * 50)

            scan_ports(target, start_port, end_port)
            print("\nScan completed!\n")
        elif choice == "2":
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()