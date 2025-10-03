<div align="center">

  `Scanix`

</div>

> [!CAUTION]
>
> ### For Learning Purposes Only
>
> This project is built for **educational purposes** and is not intended for **unauthorized scanning**.
>
> Use only on hosts and networks where you have explicit permission.

<details open="open">
<summary>Table of Contents</summary>

- [About](#about)
- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [Example](#example)
- [Disclaimer](#disclaimer)
</details>

---

## About

`Scanix` is a simple Python-based port scanner with **basic OS fingerprinting**.
It attempts to identify the operating system of a target host by analyzing **TTL values** and reports open ports in a given range.

This tool is a lightweight alternative to larger scanners and is intended for **educational and experimental** use.

## Features

- Scans a range of TCP ports on a target host
- Guesses the operating system based on **TTL values**
- Prints detected **open ports** with OS guess
- Minimal and easy-to-read Python code

## Requirements

- Python **3.7+**
- `pyfiglet` (for ASCII banner)

Install requirements:
```bash
pip install pyfiglet
```

## Usage
<div align="left">

Clone the repository

```bash
git clone https://github.com/numankhaan/scanix.git
```
Move to Project Floder
```bash
cd scanix
```
Run the script

```bash
python PortScannerwithOSFingerprint.py <ip> <start_port> <end_port>
```
</div>

## Example
<div align="left">

```bash
python PortScannerwithOSFingerprint.py example.com 1 1000
```
This will scan ports 1–1000 on the host example.com and attempt to guess the OS.
</div>

## Disclaimer

This tool is provided for educational purposes only.
Unauthorized use of port scanning on systems without permission may violate laws or policies.
