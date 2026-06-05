"""
Banner Grabber — Service Banner & Fingerprinting Tool
Author  : Rishabh Sankhla | CEH v13 | TryHackMe Top 2%
GitHub  : github.com/rishi7714
Purpose : Grab service banners from open ports to identify
          software, versions, and potential CVEs.

USAGE:
  python3 banner_grabber.py -t 192.168.1.1
  python3 banner_grabber.py -t example.com -p 22 80 443 8080
  python3 banner_grabber.py -t 192.168.1.1 --top20
  python3 banner_grabber.py -t 192.168.1.1 --all
  python3 banner_grabber.py -f targets.txt -p 22 80 443
  python3 banner_grabber.py -t example.com --timeout 5 -v --output results.json

DISCLAIMER: Authorised security testing and educational use only.
"""

import socket, ssl, sys, os, json, argparse, threading, re, time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Colours ──────────────────────────────────────────────────
class C:
    RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
    BLUE='\033[94m'; CYAN='\033[96m'; WHITE='\033[97m'
    BOLD='\033[1m'; DIM='\033[2m'; R='\033[0m'
    @staticmethod
    def off():
        C.RED=C.GREEN=C.YELLOW=C.BLUE=C.CYAN=C.WHITE=C.BOLD=C.DIM=C.R=''

# ── Port database ─────────────────────────────────────────────
PORTS = {
    21:  ("FTP",         "tcp", b""),
    22:  ("SSH",         "tcp", b""),
    23:  ("Telnet",      "tcp", b"\r\n"),
    25:  ("SMTP",        "tcp", b"EHLO test\r\n"),
    53:  ("DNS",         "tcp", b""),
    80:  ("HTTP",        "tcp", b"HEAD / HTTP/1.0\r\nHost: {h}\r\n\r\n"),
    110: ("POP3",        "tcp", b""),
    143: ("IMAP",        "tcp", b""),
    443: ("HTTPS",       "ssl", b"HEAD / HTTP/1.0\r\nHost: {h}\r\n\r\n"),
    445: ("SMB",         "tcp", b""),
    465: ("SMTPS",       "ssl", b"EHLO test\r\n"),
    587: ("SMTP/TLS",    "tcp", b"EHLO test\r\n"),
    993: ("IMAPS",       "ssl", b""),
    995: ("POP3S",       "ssl", b""),
    1433:("MSSQL",       "tcp", b""),
    2375:("Docker",      "tcp", b"GET /version HTTP/1.0\r\n\r\n"),
    3000:("Dev Server",  "tcp", b"HEAD / HTTP/1.0\r\nHost: {h}\r\n\r\n"),
    3306:("MySQL",       "tcp", b""),
    3389:("RDP",         "tcp", b""),
    5432:("PostgreSQL",  "tcp", b""),
    5900:("VNC",         "tcp", b""),
    6379:("Redis",       "tcp", b"INFO\r\n"),
    8000:("HTTP-alt",    "tcp", b"HEAD / HTTP/1.0\r\nHost: {h}\r\n\r\n"),
    8080:("HTTP-proxy",  "tcp", b"HEAD / HTTP/1.0\r\nHost: {h}\r\n\r\n"),
    8443:("HTTPS-alt",   "ssl", b"HEAD / HTTP/1.0\r\nHost: {h}\r\n\r\n"),
    8888:("HTTP-alt",    "tcp", b"HEAD / HTTP/1.0\r\nHost: {h}\r\n\r\n"),
    9200:("Elasticsearch","tcp",b"GET / HTTP/1.0\r\nHost: {h}\r\n\r\n"),
    27017:("MongoDB",    "tcp", b""),
}

TOP20 = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017,3000,8000]

# ── Service identification patterns ───────────────────────────
PATTERNS = [
    (r"SSH-\d+\.\d+-",          "SSH Server"),
    (r"OpenSSH_[\d\.]+",        "OpenSSH"),
    (r"Apache/[\d\.]+",         "Apache Web Server"),
    (r"nginx/[\d\.]+",          "Nginx Web Server"),
    (r"Microsoft-IIS/[\d\.]+",  "Microsoft IIS"),
    (r"Apache Tomcat/[\d\.]+",  "Apache Tomcat"),
    (r"vsftpd [\d\.]+",         "vsftpd FTP"),
    (r"ProFTPD [\d\.]+",        "ProFTPD"),
    (r"Postfix",                "Postfix SMTP"),
    (r"Dovecot",                "Dovecot IMAP/POP3"),
    (r"MySQL",                  "MySQL"),
    (r"PostgreSQL",             "PostgreSQL"),
    (r"MongoDB",                "MongoDB"),
    (r"Redis [\d\.]+",          "Redis"),
    (r"PHP/[\d\.]+",            "PHP"),
    (r"Ubuntu",                 "Ubuntu Linux"),
    (r"Debian",                 "Debian Linux"),
    (r"CentOS",                 "CentOS Linux"),
    (r"Windows",                "Windows Server"),
    (r"Jenkins",                "Jenkins CI/CD"),
    (r"RFB [\d\.]+",            "VNC Remote Desktop"),
]

# ── Known vulnerable version hints ────────────────────────────
CVE_HINTS = {
    "OpenSSH_7.":     "⚠  OpenSSH 7.x — CVE-2018-15473 user enumeration",
    "OpenSSH_6.":     "⚠  OpenSSH 6.x — EOL, multiple CVEs",
    "Apache/2.4.49":  "🚨 CVE-2021-41773 — Path Traversal & RCE (CRITICAL)",
    "Apache/2.4.50":  "🚨 CVE-2021-42013 — Path Traversal & RCE (CRITICAL)",
    "Apache/2.2.":    "⚠  Apache 2.2 — EOL, many CVEs",
    "PHP/5.":         "🚨 PHP 5.x — EOL, critical CVEs",
    "PHP/7.0.":       "⚠  PHP 7.0 — EOL",
    "PHP/7.1.":       "⚠  PHP 7.1 — EOL",
    "Microsoft-IIS/6.0": "🚨 IIS 6.0 — CVE-2017-7269 buffer overflow",
    "vsftpd 2.3.4":   "🚨 CVE-2011-2523 — vsftpd 2.3.4 backdoor",
}


def grab_tcp(host, port, timeout, probe=b""):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if probe:
                s.send(probe.replace(b"{h}", host.encode()))
            data = b""
            try:
                data += s.recv(1024)
                s.settimeout(0.8)
                for _ in range(3):
                    try: data += s.recv(512)
                    except: break
            except: pass
            return data.decode("utf-8", errors="replace").strip()
    except: return ""


def grab_ssl(host, port, timeout, probe=b""):
    banner, cert_info = "", {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                if cert:
                    cert_info["subject"]   = dict(x[0] for x in cert.get("subject",[]))
                    cert_info["issuer"]    = dict(x[0] for x in cert.get("issuer",[]))
                    cert_info["not_after"] = cert.get("notAfter","")
                    san = cert.get("subjectAltName",[])
                    cert_info["alt_names"] = [v for _,v in san if _ == "DNS"]
                cert_info["tls_version"] = s.version()
                cert_info["cipher"]      = s.cipher()[0] if s.cipher() else ""
                if probe:
                    s.send(probe.replace(b"{h}", host.encode()))
                    try: banner = s.read(2048).decode("utf-8",errors="replace").strip()
                    except: pass
    except: pass
    return banner, cert_info


def analyse(banner):
    identified, vulns = [], []
    if not banner: return identified, vulns
    for pattern, label in PATTERNS:
        if re.search(pattern, banner, re.IGNORECASE):
            identified.append(label)
    for key, hint in CVE_HINTS.items():
        if key.lower() in banner.lower():
            vulns.append(hint)
    return identified, vulns


def scan_port(host, port, timeout):
    info  = PORTS.get(port, ("Unknown","tcp",b""))
    name, proto, probe = info
    result = {
        "port": port, "state": "closed", "service": name,
        "protocol": proto, "banner": "", "banner_short": "",
        "ssl_info": {}, "identified": [], "vulns": [],
        "server_header": "", "x_powered_by": "",
    }

    if proto == "ssl":
        banner, ssl_info = grab_ssl(host, port, timeout, probe)
        result.update({"banner": banner, "ssl_info": ssl_info})
        if ssl_info or banner: result["state"] = "open"
    else:
        banner = grab_tcp(host, port, timeout, probe)
        result["banner"] = banner
        if banner:
            result["state"] = "open"
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((host, port)) == 0:
                        result["state"] = "open"
            except: pass

    if result["banner"]:
        result["banner_short"] = result["banner"].split("\n")[0].strip()[:120]
        result["identified"], result["vulns"] = analyse(result["banner"])
        # Extract HTTP headers
        for line in result["banner"].split("\n"):
            l = line.strip()
            if l.lower().startswith("server:"):
                result["server_header"] = l
            elif l.lower().startswith("x-powered-by:"):
                result["x_powered_by"] = l

    return result


def print_banner_header():
    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║   BANNER GRABBER v1.0  —  Service Fingerprinting Tool        ║
║   Author: Rishabh Sankhla | CEH v13 | TryHackMe Top 2%      ║
╚══════════════════════════════════════════════════════════════╝
{C.R}""")


def print_result(r, verbose=False):
    if r["state"] != "open":
        if verbose:
            print(f"  {C.DIM}{r['port']}/{r['protocol']} CLOSED{C.R}")
        return

    print(f"\n{C.BOLD}{'─'*55}{C.R}")
    print(f"  {C.CYAN}Port  :{C.R} {r['port']}/{r['protocol']}  [{C.GREEN}OPEN{C.R}]  {C.YELLOW}{r['service']}{C.R}")

    ssl = r.get("ssl_info", {})
    if ssl:
        if ssl.get("tls_version"):
            print(f"  {C.BLUE}TLS   :{C.R} {ssl['tls_version']}  |  {ssl.get('cipher','')}")
        subj = ssl.get("subject", {})
        if subj:
            print(f"  {C.BLUE}Cert  :{C.R} CN={subj.get('commonName','')}  Org={subj.get('organizationName','')}")
        if ssl.get("not_after"):
            print(f"  {C.BLUE}Expiry:{C.R} {ssl['not_after']}")
        alts = ssl.get("alt_names", [])
        if alts:
            print(f"  {C.BLUE}SANs  :{C.R} {', '.join(alts[:5])}" +
                  (f" (+{len(alts)-5} more)" if len(alts)>5 else ""))

    if r["banner_short"]:
        print(f"  {C.BLUE}Banner:{C.R} {C.WHITE}{r['banner_short']}{C.R}")

    for svc in r["identified"][:3]:
        print(f"  {C.GREEN}Found :{C.R} {svc}")

    if r["server_header"]:
        print(f"  {C.BLUE}Server:{C.R} {r['server_header']}")
    if r["x_powered_by"]:
        print(f"  {C.BLUE}Pow By:{C.R} {r['x_powered_by']}")

    for v in r["vulns"]:
        print(f"  {C.RED}{v}{C.R}")

    if verbose and r["banner"]:
        lines = [l.strip() for l in r["banner"].split("\n") if l.strip()]
        if len(lines) > 1:
            print(f"  {C.DIM}--- Full Banner ---{C.R}")
            for line in lines[:8]:
                print(f"  {C.DIM}{line}{C.R}")


def print_summary(host, ip, results, elapsed):
    open_ports = [r for r in results if r["state"] == "open"]
    print(f"\n{C.CYAN}{C.BOLD}{'═'*55}{C.R}")
    print(f"{C.BOLD}  SCAN SUMMARY{C.R}")
    print(f"{'─'*55}")
    print(f"  Target : {C.WHITE}{host}{C.R} ({ip})")
    print(f"  Scanned: {len(results)} ports  |  Open: {C.GREEN}{len(open_ports)}{C.R}  |  Time: {elapsed:.2f}s")
    if open_ports:
        print(f"\n  {C.BOLD}Open Ports:{C.R}")
        for r in open_ports:
            svc_str = f"  [{r['identified'][0]}]" if r["identified"] else ""
            bnr_str = f"  →  {r['banner_short']}" if r["banner_short"] else ""
            print(f"    {C.GREEN}{r['port']:>5}{C.R}/{r['protocol']:<3}  "
                  f"{C.YELLOW}{r['service']:<14}{C.R}{svc_str}{C.DIM}{bnr_str}{C.R}")
    print(f"{C.CYAN}{'═'*55}{C.R}\n")


def save_results(host, ip, results, outfile):
    data = {
        "target": host, "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "tool": "banner_grabber.py by Rishabh Sankhla",
        "results": [r for r in results if r["state"] == "open"],
    }
    with open(outfile, "w") as f:
        json.dump(data, f, indent=2)
    print(f"{C.GREEN}[+] Saved → {outfile}{C.R}")


def run(host, ports, timeout, threads, verbose, output=None):
    t0 = time.time()
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"{C.RED}[!] Cannot resolve '{host}': {e}{C.R}"); return

    print(f"{C.CYAN}[*]{C.R} Target: {C.BOLD}{C.WHITE}{host}{C.R} → {ip}")
    print(f"{C.CYAN}[*]{C.R} Ports : {len(ports)} | Timeout: {timeout}s | Threads: {threads}")
    print(f"{C.DIM}{'─'*55}{C.R}")

    results, lock, done = [], threading.Lock(), [0]

    def worker(p):
        r = scan_port(ip, p, timeout)
        with lock:
            results.append(r)
            done[0] += 1
            pct = int((done[0]/len(ports))*20)
            print(f"\r  [{'█'*pct}{'░'*(20-pct)}] {done[0]}/{len(ports)} ", end="", flush=True)
        return r

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(worker, p): p for p in ports}
        for f in as_completed(futures):
            r = f.result()
            if r["state"] == "open":
                print(f"\r{' '*50}\r", end="")
                print_result(r, verbose)

    print(f"\r{' '*50}\r", end="")
    elapsed = time.time() - t0
    print_summary(host, ip, results, elapsed)
    if output: save_results(host, ip, results, output)


def main():
    p = argparse.ArgumentParser(description="Banner Grabber — Service fingerprinting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 banner_grabber.py -t 192.168.1.1\n"
               "  python3 banner_grabber.py -t example.com -p 22 80 443\n"
               "  python3 banner_grabber.py -t 192.168.1.1 --top20 --output results.json")
    tg = p.add_mutually_exclusive_group(required=True)
    tg.add_argument("-t","--target")
    tg.add_argument("-f","--file")
    pg = p.add_mutually_exclusive_group()
    pg.add_argument("-p","--ports", nargs="+", type=int)
    pg.add_argument("--top20",  action="store_true")
    pg.add_argument("--all",    action="store_true")
    pg.add_argument("--range",  nargs=2, type=int, metavar=("START","END"))
    p.add_argument("--timeout",  type=int, default=3)
    p.add_argument("--threads",  type=int, default=20)
    p.add_argument("-v","--verbose", action="store_true")
    p.add_argument("--output")
    p.add_argument("--no-colour", action="store_true")
    args = p.parse_args()

    if args.no_colour or (os.name=="nt" and "ANSICON" not in os.environ): C.off()
    print_banner_header()

    if args.ports:       ports = sorted(set(args.ports))
    elif args.all:       ports = sorted(PORTS.keys())
    elif args.range:     ports = list(range(args.range[0], args.range[1]+1))
    else:                ports = sorted(TOP20)

    targets = [args.target.strip()] if args.target else []
    if args.file:
        if not os.path.isfile(args.file):
            print(f"{C.RED}[!] File not found: {args.file}{C.R}"); sys.exit(1)
        with open(args.file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    for i, target in enumerate(targets):
        if len(targets) > 1:
            print(f"\n{C.CYAN}[{i+1}/{len(targets)}] {target}{C.R}")
        outfile = None
        if args.output:
            base, ext = os.path.splitext(args.output)
            outfile = f"{base}_{target.replace('.','_')}{ext}" if len(targets)>1 else args.output
        run(target, ports, args.timeout, args.threads, args.verbose, outfile)

if __name__ == "__main__":
    main()
