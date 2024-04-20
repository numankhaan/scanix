# Port-Scanner-with-OS-Fingerprinting
This Python script is a port scanner with OS fingerprinting capabilities. It allows you to scan ports on a target host and attempt to identify the operating system running on that host based on the Time To Live (TTL) value of received packets.

# Features

  Scans a range of ports on a target host.
  Identifies the operating system running on the target host based on TTL values.
  Prints out which ports are open and the guessed operating system.
  
# How to Use

  First Clone the repository:
  
  ```git clone https://github.com/your_username/port-scanner-with-os-fingerprinting.git```
  
  Navigate to the directory:
  
  ```cd port-scanner-with-os-fingerprinting```
  
  Run the script:
  
  ```python scanner.py <ip> <start_port> <end_port>```

# Example

  ```python scanner.py example.com 1 1000```
  
  This will scan ports 1 through 1000 on the host example.com and attempt to identify the operating system.

# Disclaimer
  
  This tool is provided for educational and informational purposes only. Usage of this tool without appropriate authorization may violate laws and regulations.
  
