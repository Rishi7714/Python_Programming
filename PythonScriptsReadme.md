# 🐍 Python Security Scripts

![Python](https://img.shields.io/badge/Python-3.6+-blue?style=flat&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Ubuntu%20%7C%20Windows-purple?style=flat)
![CEH](https://img.shields.io/badge/Cert-CEH%20v13-orange?style=flat)
![TryHackMe](https://img.shields.io/badge/TryHackMe-Top%202%25-red?style=flat)
![Author](https://img.shields.io/badge/Author-Rishabh%20Sankhla-00ccff?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

> A collection of Python security tools built from scratch during my VAPT
> internship at UptoSkills and cybersecurity learning journey.
> Each script is documented, functional, and solves a real security problem.

---

## 📑 Table of Contents

- [Scripts Overview](#scripts-overview)
- [Installation](#installation)
- [Script 1 — Port Scanner](#script-1--port-scanner)
- [Script 2 — Banner Grabber](#script-2--banner-grabber)
- [Script 3 — Subdomain Checker](#script-3--subdomain-checker)
- [Script 4 — Password Strength Checker](#script-4--password-strength-checker)
- [Requirements](#requirements)
- [Learning Progression](#learning-progression)
- [Ethical Usage](#ethical-usage)
- [Author](#author)

---

## 📦 Scripts Overview

| # | Script | Purpose | Complexity |
|---|--------|---------|------------|
| 1 | `port_scanner.py` | Scan TCP ports on a target IP | Beginner |
| 2 | `banner_grabber.py` | Grab service banners from open ports | Intermediate |
| 3 | `subdomain_checker.py` | Enumerate and validate subdomains | Intermediate |
| 4 | `password_strength.py` | Analyse password security & generate strong passwords | Intermediate |

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/rishi7714/python-security-scripts.git
cd python-security-scripts

# No external dependencies — all scripts use Python standard library only!
python3 --version  # Requires Python 3.6+

# Make executable (Linux/Mac)
chmod +x port_scanner.py banner_grabber.py subdomain_checker.py password_strength.py

# Run any script
python3 port_scanner.py
python3 banner_grabber.py --help
python3 subdomain_checker.py --help
python3 password_strength.py --help
```

> **No `pip install` required.** Every script uses only Python's built-in
> standard library — `socket`, `ssl`, `urllib`, `threading`, `hashlib`, etc.

---

## Script 1 — Port Scanner

### What it does

A clean, beginner-friendly TCP port scanner. Takes a target IP and a list of
ports, attempts a TCP connection to each one, and reports which ports are
**OPEN** or **CLOSED**. This is the foundation of every network security assessment.

```
How TCP port scanning works:

  Scanner ── SYN ──────────► Target:22
  Target  ── SYN-ACK ──────► Scanner   →  Port 22 is OPEN

  Scanner ── SYN ──────────► Target:9999
  Target  ── RST ──────────► Scanner   →  Port 9999 is CLOSED
```

### The Code

```python
import socket
from datetime import datetime

def scan_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def main():
    target_ip   = input('Enter target IP address: ').strip()
    ports_input = input('Enter ports (comma-separated, e.g. 21,22,80): ')
    ports       = [int(p.strip()) for p in ports_input.split(',')]

    print(f'\n--- Port Scan Report for {target_ip} ---')
    print(f'Scan started: {datetime.now()}\n')

    open_ports = []
    for port in ports:
        is_open = scan_port(target_ip, port)
        status  = 'OPEN  [!]' if is_open else 'CLOSED'
        print(f' Port {port:5d}  →  {status}')
        if is_open:
            open_ports.append(port)

    print(f'\nTotal open ports: {len(open_ports)}')
    print(f'Scan completed: {datetime.now()}')

if __name__ == '__main__':
    main()
```

### Usage

```bash
python3 port_scanner.py
```

```
Enter target IP address: 192.168.1.1
Enter ports (comma-separated, e.g. 21,22,80): 21,22,23,80,443,8080

--- Port Scan Report for 192.168.1.1 ---
Scan started: 2026-05-01 14:30:00

 Port    21  →  CLOSED
 Port    22  →  OPEN  [!]
 Port    23  →  CLOSED
 Port    80  →  OPEN  [!]
 Port   443  →  OPEN  [!]
 Port  8080  →  CLOSED

Total open ports: 3
Scan completed: 2026-05-01 14:30:04
```

### Code Explanation — Line by Line

```python
# AF_INET  = use IPv4 addressing
# SOCK_STREAM = use TCP (reliable, connection-based protocol)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Don't wait more than 1 second per port
# Without this the script would hang on filtered/unreachable ports
sock.settimeout(timeout)

# connect_ex() returns 0  → connection succeeded → port is OPEN
# connect_ex() returns >0 → connection failed    → port is CLOSED or FILTERED
# Unlike connect(), connect_ex() does NOT raise an exception on failure
result = sock.connect_ex((ip, port))
return result == 0   # True = OPEN, False = CLOSED
```

### Common Ports Reference

```
21   → FTP        (File Transfer)
22   → SSH        (Secure Shell — remote access)
23   → Telnet     (Unencrypted remote — dangerous if open!)
25   → SMTP       (Email sending)
53   → DNS        (Domain Name System)
80   → HTTP       (Web — unencrypted)
110  → POP3       (Email receiving)
143  → IMAP       (Email)
443  → HTTPS      (Web — encrypted)
445  → SMB        (Windows file sharing)
3306 → MySQL      (Database)
3389 → RDP        (Windows Remote Desktop)
5432 → PostgreSQL (Database)
6379 → Redis      (Cache database)
8080 → HTTP-alt   (Dev servers, proxies)
27017→ MongoDB    (NoSQL database)
```

### Key Learning Points

| Concept | What It Teaches |
|---------|----------------|
| `socket.socket()` | How to create a TCP connection in Python |
| `connect_ex()` | Non-exception version of connect — returns error codes |
| `settimeout()` | Preventing the script from hanging on filtered ports |
| Port numbers | Understanding common services and what runs where |
| TCP handshake | Why returning 0 means the port accepted a connection |

### Next Steps After This Script

Once you understand `port_scanner.py`, these are natural improvements to try:

```python
# 1. Add argparse for command-line arguments instead of input()
import argparse

# 2. Add threading for faster scanning (all ports at once)
from concurrent.futures import ThreadPoolExecutor

# 3. Add a port range instead of comma-separated list
for port in range(1, 1025):  # scan ports 1–1024

# 4. Add service name lookup
services = {21:'FTP', 22:'SSH', 80:'HTTP', 443:'HTTPS', 3306:'MySQL'}
service_name = services.get(port, 'Unknown')

# 5. Combine with banner_grabber.py — for each open port, grab the banner
```

---

## Script 2 — Banner Grabber

### What it does

Connects to open ports and grabs the **service banner** — the identification
text that services send when a client connects. Used to identify software
names, version numbers, and potential CVEs.

```
SSH banner:   SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
HTTP banner:  Server: Apache/2.4.52 (Ubuntu)
FTP banner:   220 (vsFTPd 3.0.5)
MySQL banner: 8.0.32-MySQL Community Server
```

### Key Differences from port_scanner.py

| Feature | `port_scanner.py` | `banner_grabber.py` |
|---------|-------------------|---------------------|
| Open/closed detection | ✅ | ✅ |
| Service name | ❌ | ✅ |
| Software version | ❌ | ✅ (from banner) |
| CVE hints | ❌ | ✅ |
| SSL cert details | ❌ | ✅ |
| HTTP header analysis | ❌ | ✅ |
| Multi-threaded | ❌ | ✅ |
| Best for | Learning basics | Real VAPT work |

### Usage

```bash
# Scan top-20 common ports
python3 banner_grabber.py -t 192.168.1.1

# Scan specific ports
python3 banner_grabber.py -t example.com -p 22 80 443 8080 3306

# Scan all pre-defined ports (~35 services)
python3 banner_grabber.py -t 192.168.1.1 --all

# Scan multiple targets from file
python3 banner_grabber.py -f targets.txt --top20

# Save results to JSON
python3 banner_grabber.py -t 192.168.1.1 --output results.json

# Verbose mode — show full banners and closed ports
python3 banner_grabber.py -t 192.168.1.1 -v --timeout 5
```

### Sample Output

```
[*] Target: 192.168.1.100  |  Ports: 20  |  Threads: 20

──────────────────────────────────────────────────────
  Port  : 22/tcp  [OPEN]  SSH
  Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
  Found : OpenSSH

──────────────────────────────────────────────────────
  Port  : 80/tcp  [OPEN]  HTTP
  Server: Server: Apache/2.4.52 (Ubuntu)
  Found : Apache Web Server

──────────────────────────────────────────────────────
  Port  : 443/tcp  [OPEN]  HTTPS
  TLS   : TLSv1.3  |  TLS_AES_256_GCM_SHA384
  Cert  : CN=example.com  Org=Example Corp
  Expiry: Dec 15 23:59:59 2026 GMT

  SCAN SUMMARY
  Target : 192.168.1.100
  Open   : 3  |  Time: 4.23s
```

---

## Script 3 — Subdomain Checker

### What it does

Discovers active subdomains of a target domain using DNS brute-forcing,
HTTP/HTTPS probing, and certificate transparency log queries. Used in
VAPT reconnaissance to map the full external attack surface.

```
Why subdomains matter in security:

  main site:    example.com           → Secure, well-maintained
  dev subdomain: dev.example.com      → Often less secure, exposed
  old subdomain: legacy.example.com   → Forgotten, unpatched
  admin panel:   admin.example.com    → High-value target
```

### Features

- ✅ Built-in wordlist (100+ common subdomains — no file needed)
- ✅ DNS resolution with A and AAAA records
- ✅ HTTP/HTTPS probing — status codes, titles, server headers
- ✅ Certificate Transparency via `crt.sh` API
- ✅ Private IP detection and flagging
- ✅ Interesting subdomain flagging (admin, dev, staging, api...)
- ✅ Multi-threaded with live progress bar
- ✅ Output to `.txt` or `.json`

### Usage

```bash
# Use built-in wordlist (easiest — no file needed)
python3 subdomain_checker.py -d example.com --builtin

# Use your own wordlist
python3 subdomain_checker.py -d example.com -w wordlist.txt

# Probe HTTP/HTTPS (get page titles and server info)
python3 subdomain_checker.py -d example.com --builtin --http

# Query certificate transparency logs (find more subdomains)
python3 subdomain_checker.py -d example.com --builtin --crt

# Full scan — wordlist + CT logs + HTTP probing
python3 subdomain_checker.py -d example.com --builtin --http --crt

# Fast scan with more threads
python3 subdomain_checker.py -d example.com --builtin --threads 50

# Save to file
python3 subdomain_checker.py -d example.com --builtin --output found.txt
python3 subdomain_checker.py -d example.com --builtin --output results.json
```

### Sample Output

```
[*] Target: example.com
[*] Checking 108 subdomains | Threads: 30

[+] www.example.com
    IP  : 93.184.216.34
    HTTPS: 200 OK  |  "Welcome to Example"

[+] api.example.com  ★ INTERESTING
    IP  : 93.184.216.35
    HTTPS: 200 OK  |  "API Gateway v2"

[+] dev.example.com  ★ INTERESTING
    IP  : 10.0.0.50 [PRIVATE IP]

  SUBDOMAIN SCAN SUMMARY
  Checked    : 108  |  Active: 12  |  Interesting: 5
  Time       : 23.4s
```

---

## Script 4 — Password Strength Checker

### What it does

Comprehensive password security analysis. Scores passwords, detects weak
patterns, estimates crack times under different attack scenarios, checks
against breach databases, and generates secure passwords.

```
Password entropy:

  "cat"            → 14 bits  → cracked instantly
  "C@t9#mK2!xPq"  → 78 bits  → 400+ years (GPU attack)
  "tiger.lunar.quest.solar.42"  → 89 bits  → practically uncrackable
```

### Features

- ✅ Score 0–100 with grade (F to A+)
- ✅ Entropy calculation in bits
- ✅ Crack time for 4 attack scenarios
- ✅ 200+ common password detection (inc. leet-speak variants)
- ✅ Keyboard walk detection (qwerty, asdf, 12345...)
- ✅ **HaveIBeenPwned API** using k-anonymity (password never transmitted!)
- ✅ Custom policy enforcement
- ✅ Password generator (mixed, passphrase, memorable styles)
- ✅ Batch file checking with summary report

### Usage

```bash
# Interactive secure input (recommended)
python3 password_strength.py

# Check a specific password
python3 password_strength.py -p "MyPassword123!"

# Check + HaveIBeenPwned breach lookup
python3 password_strength.py -p "password123" --hibp

# Batch check a file of passwords
python3 password_strength.py -f passwords.txt --hibp --output audit.json

# Generate a strong password
python3 password_strength.py --generate
python3 password_strength.py --generate --style passphrase --count 3
python3 password_strength.py --generate --length 20
```

### Sample Output

```
══════════════════════════════════════════════════════════════
  PASSWORD ANALYSIS
──────────────────────────────────────────────────────────────
  Password : ************  (12 characters)
  Score    : [████████████████████░░░░░░░░░░] 72/100
  Strength : Good   Grade: B
  Entropy  : 78.3 bits

  Character Analysis:
    ✓  Lowercase letters (a-z)
    ✓  Uppercase letters (A-Z)
    ✓  Digits (0-9)
    ✓  Special characters (!@#...)
    ✓  Length ≥ 12 (12 chars)

  Estimated Crack Times:
    Online (throttled)      : Longer than age of universe
    Offline (MD5/SHA1)      : 4.1 hours

  HaveIBeenPwned Check:
    ✓ Not found — Not in any known data breaches
══════════════════════════════════════════════════════════════
```

---

## 📋 Requirements

```
Python version : 3.6 or higher
Dependencies   : NONE — standard library only

Modules used across all scripts:
  socket      — TCP connections, DNS resolution
  ssl         — SSL/TLS connections and certificate reading
  urllib      — HTTP requests (no requests library needed)
  threading   — Concurrent scanning for speed
  hashlib     — SHA-1 hashing for HIBP k-anonymity
  secrets     — Cryptographically secure password generation
  argparse    — Command-line argument parsing
  getpass     — Secure password input (hidden from terminal)
  json        — Output formatting and saving results
  re          — Regular expression pattern matching
  math        — Entropy calculation (log2)

Optional (internet connection required):
  HaveIBeenPwned API  →  password_strength.py --hibp
  crt.sh API          →  subdomain_checker.py --crt
```

---

## 🗺️ Learning Progression

These scripts are designed to build on each other. Work through them in order:

```
BEGINNER:
  port_scanner.py
  ↓ Concepts: sockets, TCP, connect_ex(), port numbers

INTERMEDIATE:
  banner_grabber.py
  ↓ Concepts: recv(), SSL wrapping, regex, service identification

  subdomain_checker.py
  ↓ Concepts: DNS (getaddrinfo), threading, urllib HTTP requests

  password_strength.py
  ↓ Concepts: entropy (log2), hashlib, REST API (HIBP), secrets module

PROJECTS TO BUILD NEXT:
  → Add threading to port_scanner.py (5× speed improvement)
  → Pipe port_scanner output into banner_grabber automatically
  → Build a network mapper combining all 4 tools
  → Add Shodan API integration to subdomain_checker.py
  → Add SQLite storage to save scan history
```

---

## 🔧 Troubleshooting

```bash
# All ports show CLOSED even for known-open ports
# → Check firewall/network path, verify target IP is reachable
ping TARGET_IP

# banner_grabber.py is very slow
# → Reduce timeout, increase threads
python3 banner_grabber.py -t TARGET --timeout 2 --threads 30

# subdomain_checker.py misses known subdomains
# → Add --crt flag to use certificate transparency logs
# → Try a larger wordlist (SecLists)
python3 subdomain_checker.py -d example.com --builtin --crt

# HIBP check fails
# → Check internet connection
# → HIBP may be temporarily unavailable — try again

# No colours on Windows
# → Use Windows Terminal, or add --no-colour flag
python3 banner_grabber.py -t TARGET --no-colour
```

---

## ⚠️ Ethical Usage

> **These tools are for authorised security testing and educational use ONLY.**

- Always get **written permission** before scanning systems you don't own
- `port_scanner.py` — only scan your own systems or authorised targets
- `banner_grabber.py` — same — only on systems you have permission to test
- `subdomain_checker.py` — only enumerate domains you own or are authorised to test
- `password_strength.py` — safe to use on any passwords locally

The HaveIBeenPwned check uses **k-anonymity**: only the first 5 characters of
the SHA-1 hash are sent to the API. Your actual password never leaves your machine.

Unauthorised scanning may violate computer crime laws:
India: IT Act 2000 | US: CFAA | UK: Computer Misuse Act 1990

---

## 👤 Author

**Rishabh Sankhla**
- 🛡️ Certified Ethical Hacker (CEH v13) — EC-Council
- 🔴 CRTOM — Red Team Leaders
- 🏆 Top 2% Globally — TryHackMe (Risank7714)
- 💼 VAPT Intern & Assistant Captain @ UptoSkills
- 🎓 MCA — Aishwarya College, Jodhpur, Rajasthan

**Connect:**
- 🔗 [LinkedIn](https://linkedin.com/in/rishabhsankhla771401)
- 🔒 [TryHackMe](https://tryhackme.com/p/Risank7714)

---

## 📄 License

MIT License — Free to use, modify, and distribute with attribution.

---

*Last Updated: May 2026 | Python 3.6+ | No external dependencies*
