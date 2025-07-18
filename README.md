## 1.Port Scanner Without Using `nmap` Module (Python)

A basic TCP port scanner using Python’s `socket` module.

```python
import socket

def basic_port_scanner(ip, start_port, end_port):
    print(f"Scanning {ip} from port {start_port} to {end_port}")
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"[+] Port {port} is OPEN")
```

---
## 2.Port Scanner Using `nmap` Module (Python)

A scanner using the `python-nmap` module.

```python
import nmap

def nmap_port_scanner(ip, port_range):
    scanner = nmap.PortScanner()
    scanner.scan(ip, port_range)

    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            for port in scanner[host][proto].keys():
                state = scanner[host][proto][port]['state']
                print(f"Port: {port}	State: {state}")s
```

---
## 3. About `python-nmap` Module

### What is `python-nmap`?
- A Python wrapper around the Nmap command-line tool.
- Enables you to control Nmap from Python code.

### Key Methods and Usage
| `nmap.PortScanner()` | Creates a new scanner object |---

| `.scan(hosts, ports)` | Scans the host/port range |---

| `.all_hosts()` | Lists all scanned hosts |---

| `.hostname()` | Returns DNS name |---

| `.state()` | Returns host state (up/down) |---

| `.all_protocols()` | Returns `tcp` or `udp` |---

| `[proto][port]['state']` | Port status (`open`, `closed`, etc.) |---

| `--script` | Pass NSE scripts to the scan |---


### Requirements
- `nmap` must be installed on your system.
- Install wrapper with:
  ```bash
  pip install python-nmap
  ```

---

## 4. Host Discovery Tool (Gateway IP + IP Class) in Python

```python
import socket
import os
import ipaddress

def get_gateway_ip():
    route = os.popen("ip route show").read()
    for line in route.splitlines():
        if "default via" in line:
            return line.split()[2]
    return None

def get_ip_class(ip):
    first_octet = int(ip.split(".")[0])
    if 1 <= first_octet <= 126:
        return "Class A"
    elif 128 <= first_octet <= 191:
        return "Class B"
    elif 192 <= first_octet <= 223:
        return "Class C"
    else:
        return "Class D or E"

def host_discovery():
    gateway = get_gateway_ip()
    if gateway:
        print(f"Default Gateway IP: {gateway}")
        print(f"IP Class: {get_ip_class(gateway)}")
    else:
        print("Gateway not found.")

host_discovery()
```

---

## 5. Bash Tool: Run Nmap with NSE Script

```bash
#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <IP> <NSE Script Name>"
    exit 1
fi

TARGET_IP=$1
NSE_SCRIPT=$2

echo "[*] Running Nmap with script: $NSE_SCRIPT on $TARGET_IP"
nmap --script=$NSE_SCRIPT $TARGET_IP -v
```

### Make It Executable
```bash
chmod +x nse_scan.sh
```

---

##
