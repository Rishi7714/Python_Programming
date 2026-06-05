"""
Subdomain Checker — Subdomain Enumeration & Validation Tool
Author  : Rishabh Sankhla | CEH v13 | TryHackMe Top 2%
GitHub  : github.com/rishi7714
Purpose : Discover and validate active subdomains using DNS
          resolution, HTTP probing, and certificate transparency.

USAGE:
  python3 subdomain_checker.py -d example.com --builtin
  python3 subdomain_checker.py -d example.com -w wordlist.txt
  python3 subdomain_checker.py -d example.com --builtin --http --crt
  python3 subdomain_checker.py -d example.com --builtin --output found.txt
  python3 subdomain_checker.py -d example.com --builtin --threads 50

DISCLAIMER: Authorised security testing and educational use only.
"""

import socket, ssl, sys, os, json, argparse, threading, time
import urllib.request, urllib.error
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

# ── Built-in wordlist ─────────────────────────────────────────
WORDLIST = [
    "www","mail","ftp","webmail","smtp","pop","ns1","ns2","ns3","ns4",
    "imap","pop3","vpn","m","mobile","dev","development","test","testing",
    "qa","uat","staging","stage","beta","alpha","demo","sandbox","preview",
    "temp","tmp","local","admin","administrator","panel","control","manage",
    "management","dashboard","portal","console","cpanel","whm","plesk",
    "webmin","api","api2","api3","v1","v2","v3","rest","graphql","ws",
    "git","gitlab","github","bitbucket","ci","cd","jenkins","travis",
    "docker","k8s","kubernetes","monitor","monitoring","grafana","kibana",
    "metrics","logs","logging","sentry","db","database","mysql","postgres",
    "mongodb","redis","elastic","elasticsearch","phpmyadmin","pma",
    "cdn","static","assets","media","images","img","files","uploads",
    "download","downloads","storage","bucket","backup","backups","s3",
    "blob","archive","chat","support","helpdesk","ticket","tickets",
    "crm","erp","billing","invoice","autodiscover","autoconfig","email",
    "remote","rdp","ssh","bastion","firewall","proxy","gateway","auth",
    "login","sso","oauth","ldap","status","health","uptime","ping",
    "blog","news","forum","wiki","shop","store","pay","payment",
    "app","apps","web","site","www1","www2","www3","mail1","mail2",
    "server1","server2","node1","node2","us","eu","uk","asia","au",
    "in","de","fr","sg","jp","old","new","legacy","internal","external",
    "public","private","corp","intranet","extranet","home","smtp2",
    "mx","exchange","office","remote2","vpn2","test2","test3",
]

# Keywords that make a subdomain "interesting" / high-value
INTERESTING = [
    "admin","administrator","panel","dashboard","console","control",
    "manage","phpmyadmin","pma","dev","development","staging","test",
    "beta","qa","api","vpn","remote","git","gitlab","jenkins",
    "db","database","mysql","backup","internal","secret","private",
    "corp","intranet","auth","login","sso","monitor","grafana",
    "kibana","elastic","redis","jenkins","docker","kubernetes","k8s",
    "legacy","old","sandbox","demo",
]


# ── DNS Resolution ────────────────────────────────────────────
def resolve(subdomain, timeout=3):
    socket.setdefaulttimeout(timeout)
    ips = []
    try:
        infos = socket.getaddrinfo(subdomain, None, socket.AF_INET)
        ips = list(set(i[4][0] for i in infos))
    except: pass
    cname = ""
    try:
        c = socket.getfqdn(subdomain)
        if c and c != subdomain: cname = c
    except: pass
    return ips, cname


# ── HTTP Probing ──────────────────────────────────────────────
def probe_http(subdomain, timeout=5):
    result = {"https": None, "http": None, "title": "", "server": ""}
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (SubdomainChecker/1.0)"})
            ctx = ssl_ctx if scheme == "https" else None
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                code = r.status
                result[scheme] = code
                if not result["server"]:
                    result["server"] = r.headers.get("Server", "")
                if not result["title"]:
                    try:
                        import re
                        body = r.read(4096).decode("utf-8", errors="replace")
                        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I|re.S)
                        if m: result["title"] = re.sub(r'\s+', ' ', m.group(1).strip()[:80])
                    except: pass
        except urllib.error.HTTPError as e:
            result[scheme] = e.code
        except: pass
    return result


# ── Certificate Transparency (crt.sh) ────────────────────────
def fetch_crt_sh(domain, timeout=10):
    subs = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
            for entry in data:
                for name in entry.get("name_value","").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") and name != domain:
                        subs.add(name)
    except: pass
    return sorted(subs)


# ── IP Classification ─────────────────────────────────────────
def classify_ip(ip):
    p = ip.split(".")
    if len(p) != 4: return "unknown"
    try:
        a, b = int(p[0]), int(p[1])
        if a == 10: return "private"
        if a == 172 and 16 <= b <= 31: return "private"
        if a == 192 and b == 168: return "private"
        if a == 127: return "loopback"
        return "public"
    except: return "unknown"


# ── Check one subdomain ────────────────────────────────────────
def check_sub(prefix, domain, http_probe, dns_timeout, http_timeout):
    full = f"{prefix}.{domain}" if not prefix.endswith(f".{domain}") else prefix
    ips, cname = resolve(full, dns_timeout)
    result = {
        "subdomain": full, "prefix": prefix,
        "active": bool(ips), "ip_list": ips,
        "cname": cname,
        "ip_class": classify_ip(ips[0]) if ips else "",
        "interesting": any(kw in full.lower() for kw in INTERESTING),
        "http": {},
    }
    if ips and http_probe:
        result["http"] = probe_http(full, http_timeout)
    return result


# ── Display ───────────────────────────────────────────────────
def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║   SUBDOMAIN CHECKER v1.0  —  Enumeration & Validation Tool   ║
║   Author: Rishabh Sankhla | CEH v13 | TryHackMe Top 2%      ║
╚══════════════════════════════════════════════════════════════╝
{C.R}""")


def print_found(r, show_http):
    sub  = r["subdomain"]
    ips  = ", ".join(r["ip_list"])
    cls  = r["ip_class"]
    flag = f" {C.RED}★ INTERESTING{C.R}" if r["interesting"] else ""
    ip_col = C.YELLOW if cls in ("private","loopback") else C.WHITE
    note   = f" [{cls.upper()} IP]" if cls in ("private","loopback") else ""

    print(f"\n{C.GREEN}[+]{C.R} {C.BOLD}{C.WHITE}{sub}{C.R}{flag}")
    print(f"    IP  : {ip_col}{ips}{C.R}{note}")
    if r["cname"] and r["cname"] != sub:
        print(f"    CNAME: {C.DIM}{r['cname']}{C.R}")

    if show_http and r.get("http"):
        h = r["http"]
        for scheme in ["https","http"]:
            code = h.get(scheme)
            if code:
                col = C.GREEN if code==200 else (C.YELLOW if code<400 else C.RED)
                line = f"    {scheme.upper()}: {col}{code}{C.R}"
                if h.get("title") and scheme=="https":
                    line += f'  |  "{C.CYAN}{h["title"]}{C.R}"'
                print(line)
        if h.get("server"):
            print(f"    SRV : {C.DIM}{h['server']}{C.R}")


def print_summary(domain, results, elapsed, source, crt_count):
    active      = [r for r in results if r["active"]]
    interesting = [r for r in active  if r["interesting"]]
    private_ip  = [r for r in active  if r["ip_class"]=="private"]
    http_ok     = [r for r in active
                   if r.get("http",{}).get("https")==200
                   or r.get("http",{}).get("http")==200]

    print(f"\n{C.CYAN}{C.BOLD}{'═'*55}{C.R}")
    print(f"{C.BOLD}  SUBDOMAIN SCAN SUMMARY{C.R}")
    print(f"{'─'*55}")
    print(f"  Domain     : {C.WHITE}{domain}{C.R}")
    print(f"  Source     : {source}")
    if crt_count:
        print(f"  crt.sh     : {crt_count} subdomains from CT logs")
    print(f"  Checked    : {C.WHITE}{len(results)}{C.R}")
    print(f"  Active     : {C.GREEN}{len(active)}{C.R}")
    print(f"  Interesting: {C.RED}{len(interesting)}{C.R}")
    if http_ok:   print(f"  HTTP 200   : {C.GREEN}{len(http_ok)}{C.R}")
    if private_ip:print(f"  Private IP : {C.YELLOW}{len(private_ip)}{C.R}")
    print(f"  Time       : {elapsed:.2f}s")

    if active:
        print(f"\n  {C.BOLD}Active Subdomains:{C.R}")
        for r in sorted(active, key=lambda x: x["subdomain"]):
            flag = f" {C.RED}★{C.R}" if r["interesting"] else ""
            ips  = ", ".join(r["ip_list"])
            print(f"    {C.GREEN}{r['subdomain']:<40}{C.R} → {ips}{flag}")
    print(f"{C.CYAN}{'═'*55}{C.R}\n")


def save_results(domain, results, outfile):
    active = [r for r in results if r["active"]]
    ext = os.path.splitext(outfile)[1].lower()
    if ext == ".json":
        data = {"domain":domain,"timestamp":datetime.now().isoformat(),
                "tool":"subdomain_checker.py by Rishabh Sankhla",
                "count":len(active),"subdomains":active}
        with open(outfile,"w") as f: json.dump(data,f,indent=2)
    else:
        with open(outfile,"w") as f:
            for r in sorted(active, key=lambda x: x["subdomain"]):
                f.write(r["subdomain"]+"\n")
    print(f"{C.GREEN}[+] Saved → {outfile} ({len(active)} active){C.R}")


# ── Main scan ────────────────────────────────────────────────
def run_scan(domain, wordlist, http_probe, use_crt, threads,
             dns_timeout, http_timeout, output=None):
    t0 = time.time()
    crt_count = 0

    print(f"{C.CYAN}[*]{C.R} Target: {C.BOLD}{C.WHITE}{domain}{C.R}")

    if use_crt:
        print(f"{C.CYAN}[*]{C.R} Querying crt.sh certificate transparency logs...")
        crt_subs = fetch_crt_sh(domain)
        crt_count = len(crt_subs)
        if crt_subs:
            print(f"{C.GREEN}[+]{C.R} crt.sh found {crt_count} subdomains")
            for sub in crt_subs:
                prefix = sub.replace(f".{domain}","")
                if prefix and prefix not in wordlist:
                    wordlist.append(prefix)
        else:
            print(f"{C.DIM}[-] crt.sh returned no results{C.R}")

    wordlist = sorted(set(wordlist))
    total = len(wordlist)

    print(f"{C.CYAN}[*]{C.R} Checking {C.WHITE}{total}{C.R} subdomains | "
          f"Threads: {threads} | DNS timeout: {dns_timeout}s", end="")
    if http_probe: print(f" | HTTP probing: {C.GREEN}ON{C.R}")
    else:          print()
    print(f"{C.DIM}{'─'*55}{C.R}")

    results, lock, done = [], threading.Lock(), [0]

    def worker(prefix):
        r = check_sub(prefix, domain, http_probe, dns_timeout, http_timeout)
        with lock:
            results.append(r)
            done[0] += 1
            pct = int((done[0]/total)*25)
            found_count = sum(1 for x in results if x["active"])
            print(f"\r  [{'█'*pct}{'░'*(25-pct)}] {done[0]}/{total}  "
                  f"Found: {found_count}  ", end="", flush=True)
        return r

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(worker, p): p for p in wordlist}
        for future in as_completed(futures):
            r = future.result()
            if r["active"]:
                print(f"\r{' '*60}\r", end="")
                print_found(r, http_probe)

    print(f"\r{' '*60}\r", end="")
    elapsed = time.time() - t0
    source  = f"Wordlist ({total} entries)" + (" + crt.sh" if use_crt else "")
    print_summary(domain, results, elapsed, source, crt_count)

    if output: save_results(domain, results, output)
    return results


# ── Argument parsing ─────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="Subdomain Checker — Enumerate and validate subdomains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 subdomain_checker.py -d example.com --builtin\n"
               "  python3 subdomain_checker.py -d example.com -w wordlist.txt --http --crt\n"
               "  python3 subdomain_checker.py -d example.com --builtin --threads 50 --output found.txt")

    p.add_argument("-d","--domain", required=True, help="Target domain (e.g. example.com)")

    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-w","--wordlist", help="Wordlist file (one prefix per line)")
    src.add_argument("-l","--list",     help="Pre-built list of full subdomains")
    src.add_argument("--builtin", action="store_true", help="Use built-in wordlist (100+ entries)")

    p.add_argument("--http",     action="store_true", help="Probe each subdomain via HTTP/HTTPS")
    p.add_argument("--crt",      action="store_true", help="Query crt.sh certificate transparency")
    p.add_argument("--threads",  type=int, default=30, help="Concurrent threads (default: 30)")
    p.add_argument("--dns-timeout",  type=int, default=3,  help="DNS timeout in seconds (default: 3)")
    p.add_argument("--http-timeout", type=int, default=5,  help="HTTP timeout in seconds (default: 5)")
    p.add_argument("--output",   help="Save results (.txt or .json)")
    p.add_argument("--no-colour", action="store_true")
    args = p.parse_args()

    if args.no_colour or (os.name=="nt" and "ANSICON" not in os.environ): C.off()
    print_banner()

    domain = args.domain.lower().strip()
    if "://" in domain: domain = domain.split("//")[1].split("/")[0]

    # Build wordlist
    wordlist = []
    if args.builtin:
        wordlist = list(WORDLIST)
        src_label = f"built-in wordlist ({len(wordlist)} entries)"
    elif args.wordlist:
        if not os.path.isfile(args.wordlist):
            print(f"{C.RED}[!] File not found: {args.wordlist}{C.R}"); sys.exit(1)
        with open(args.wordlist, encoding="utf-8", errors="replace") as f:
            wordlist = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        src_label = f"'{args.wordlist}' ({len(wordlist)} entries)"
    elif args.list:
        if not os.path.isfile(args.list):
            print(f"{C.RED}[!] File not found: {args.list}{C.R}"); sys.exit(1)
        with open(args.list, encoding="utf-8", errors="replace") as f:
            raw = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        for sub in raw:
            wordlist.append(sub.replace(f".{domain}","") if sub.endswith(f".{domain}") else sub)
        src_label = f"'{args.list}' ({len(wordlist)} entries)"

    if not wordlist:
        print(f"{C.RED}[!] No subdomains to check.{C.R}"); sys.exit(1)

    print(f"{C.CYAN}[*]{C.R} Source: {src_label}")

    run_scan(domain=domain, wordlist=wordlist,
             http_probe=args.http, use_crt=args.crt,
             threads=args.threads, dns_timeout=args.dns_timeout,
             http_timeout=args.http_timeout, output=args.output)

if __name__ == "__main__":
    main()
