<div align="center">

  `Scanix`
  
  Fast, modular port scanner and network reconnaissance tool written in Python.

</div>

<details open="open">
<summary>Table of Contents</summary>

- [About](#about)
- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [Example](#example)
- [Disclaimer](#disclaimer)
</details>

## About
 
Scanix is a fast, modular network scanner written in Python. It discovers open ports, identifies running services and versions, performs OS fingerprinting, and supports multiple scanning techniques including TCP connect, SYN scan, and UDP probing.
Scanix is designed for security professionals, researchers, and developers who need a transparent, extensible scanning tool.
 

 
## Features
* TCP connect scanning
* SYN scanning (raw packets)
* UDP probing
* Service and version detection
* Basic OS fingerprinting
* Host discovery and traceroute
* Parallel scanning for high speed
* JSON, CSV, and HTML output

 
## Installation
 
```bash
git clone https://github.com/numankhaan/scanix.git
cd scanix
 
python3 -m venv venv
source venv/bin/activate
 
pip install -r requirements.txt
```
 
## Quick Start
1. Basic scan:
```bash
    python -m scanix scan -t scanme.nmap.org -p 1-1000
```
2. Service detection (banner grabbing):
```bash
    python -m scanix scan -t scanme.nmap.org -p 1-1000 --banner
```
3. SYN scan (requires root):
```bash
    sudo python -m scanix scan -t scanme.nmap.org -p 1-1000 --syn
```
4. Host discovery:
```bash
    python -m scanix discover -n 192.168.1.0/24
```
5. Traceroute:
```bash
    python -m scanix traceroute -t scanme.nmap.org
```
 
## Disclaimer
 
This tool is provided for educational purposes only.
Unauthorized use of port scanning on systems without permission may violate laws or policies.
Use Scanix only on systems you own or have explicit permission to test.
