#!/usr/bin/env python3
"""Syntecxhub CVE Scanner - lightweight banner grabber + CVE matcher.

USE ONLY ON SYSTEMS YOU OWN OR HAVE WRITTEN PERMISSION TO TEST.
Banner-based matching gives *possible* matches only (distros backport fixes
without changing version strings), so every finding needs manual triage.
"""
import argparse, datetime, ipaddress, json, os, re, socket, ssl, sys, time
import urllib.error, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 993, 995, 3306,
                 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]
HTTP_PORTS = {80, 8000, 8080, 8081, 8888, 9200}
TLS_PORTS = {443, 8443, 993, 995, 465}

# (label, regex with named group "version", cpe vendor, cpe product)
SIGNATURES = [
    ("OpenSSH", r"OpenSSH[_-](?P<version>\d+(?:\.\d+)*(?:p\d+)?)", "openbsd", "openssh"),
    ("Apache httpd", r"Apache/(?P<version>\d+(?:\.\d+)+)", "apache", "http_server"),
    ("nginx", r"nginx/(?P<version>\d+(?:\.\d+)+)", "f5", "nginx"),
    ("vsftpd", r"vsFTPd (?P<version>\d+(?:\.\d+)+)", "beasts", "vsftpd"),
    ("ProFTPD", r"ProFTPD (?P<version>\d+(?:\.\d+)+[a-z]?)", "proftpd", "proftpd"),
    ("Exim", r"Exim (?P<version>\d+(?:\.\d+)+)", "exim", "exim"),
    ("lighttpd", r"lighttpd/(?P<version>\d+(?:\.\d+)+)", "lighttpd", "lighttpd"),
    ("PHP", r"PHP/(?P<version>\d+(?:\.\d+)+)", "php", "php"),
    ("OpenSSL", r"OpenSSL/(?P<version>\d+\.\d+\.\d+[a-z]?)", "openssl", "openssl"),
    ("Microsoft IIS", r"Microsoft-IIS/(?P<version>\d+\.\d+)", "microsoft", "internet_information_services"),
]


# ----------------------------------------------------------------- scanning
def grab_banner(host, port, timeout=3.0):
    """Connect and return whatever the service volunteers (or answers to a probe)."""
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        sock = raw
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False          # scanner: we want banners, not trust
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
        sock.settimeout(timeout)
        if port in HTTP_PORTS or (port in TLS_PORTS and port not in (993, 995, 465)):
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: syntecxhub-scanner\r\n\r\n".encode())
        data = b""
        try:
            data = sock.recv(2048)
        except socket.timeout:
            pass
        return data.decode("latin-1", "replace").strip()
    except (OSError, ssl.SSLError):
        return ""
    finally:
        try:
            raw.close()
        except OSError:
            pass


def detect_services(port, banner):
    """Return list of dicts {label, version, vendor, product} found in a banner."""
    found = []
    for label, rx, vendor, product in SIGNATURES:
        m = re.search(rx, banner or "", re.I)
        if m:
            found.append(dict(label=label, version=m.group("version"), vendor=vendor, product=product))
    if port == 3306 and banner and not found:          # MySQL/MariaDB greeting contains version
        m = re.search(r"(\d+\.\d+\.\d+)(-MariaDB)?", banner)
        if m:
            found.append(dict(label="MariaDB" if m.group(2) else "MySQL", version=m.group(1),
                              vendor="mariadb" if m.group(2) else "oracle",
                              product="mariadb" if m.group(2) else "mysql"))
    return found


# ------------------------------------------------------------ CVE look-ups
def severity_from_score(score):
    if score is None: return "UNKNOWN"
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0: return "LOW"
    return "NONE"


def parse_ver(v):
    m = re.fullmatch(r"(\d+(?:\.\d+)*)([a-z])?", v.lower())
    if m:
        t = tuple(int(x) for x in m.group(1).split("."))
        return t + ((ord(m.group(2)) - 96,) if m.group(2) else ())
    return tuple(int(x) for x in re.findall(r"\d+", v))


def to_cpe(vendor, product, version):
    m = re.fullmatch(r"(\d+(?:\.\d+)*)(p\d+)", version)       # 8.2p1 -> 8.2 : p1
    ver, upd = (m.group(1), m.group(2)) if m else (version, None)
    return f"cpe:2.3:a:{vendor}:{product}:{ver}" + (f":{upd}" if upd else "")


def query_nvd(cpe, api_key=None, cache=None, timeout=20):
    if cache is not None and cpe in cache:
        return cache[cpe]
    url = f"{NVD_URL}?{urllib.parse.urlencode({'virtualMatchString': cpe, 'resultsPerPage': 100})}&noRejected"
    headers = {"User-Agent": "syntecxhub-cve-scanner/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as r:
        data = json.load(r)
    out = []
    for item in data.get("vulnerabilities", []):
        c = item["cve"]
        score = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if c.get("metrics", {}).get(key):
                score = c["metrics"][key][0]["cvssData"]["baseScore"]
                break
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        out.append(dict(cve=c["id"], score=score, severity=severity_from_score(score),
                        summary=desc[:300], published=c.get("published", "")[:10],
                        kev=bool(c.get("cisaExploitAdd")), source="NVD API",
                        url=f"https://nvd.nist.gov/vuln/detail/{c['id']}"))
    out.sort(key=lambda x: (x["score"] or 0), reverse=True)
    if cache is not None:
        cache[cpe] = out
    time.sleep(0.7 if api_key else 6.5)        # NVD public rate limit: 5 req / 30 s
    return out


def load_offline_db(path=None):
    with open(path or os.path.join(HERE, "data", "signatures.json"), encoding="utf-8") as f:
        return json.load(f)


def match_offline(db, vendor, product, version):
    key, v, res = f"{vendor}/{product}", parse_ver(version), []
    for e in db:
        if e["product"] != key:
            continue
        if "min" in e and v < parse_ver(e["min"]): continue
        if "max_inclusive" in e and v > parse_ver(e["max_inclusive"]): continue
        if "max_exclusive" in e and v >= parse_ver(e["max_exclusive"]): continue
        res.append(dict(cve=e["cve"], score=e["score"], severity=severity_from_score(e["score"]),
                        summary=e["summary"], published="", kev=e.get("kev", False),
                        source="offline signatures (approx. score - verify on NVD)",
                        url=f"https://nvd.nist.gov/vuln/detail/{e['cve']}"))
    return sorted(res, key=lambda x: x["score"], reverse=True)


# --------------------------------------------------------------- reporting
ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"]
TRIAGE = {
    "CRITICAL": "P1 - verify immediately; patch/isolate within 24-48h. Check if internet-exposed.",
    "HIGH": "P2 - verify this week; schedule patch, add compensating controls (firewall/WAF).",
    "MEDIUM": "P3 - patch in the next regular maintenance window.",
    "LOW": "P4 - track; fix opportunistically.",
}


def render_markdown(report):
    L = [f"# Syntecxhub CVE Scan Report", "",
         f"- **Target:** {report['target']} ({report['ip']})",
         f"- **Date:** {report['date']}", f"- **Mode:** {report['mode']}",
         f"- **Open ports scanned:** {len(report['services'])}", "",
         "> Matches are *possible* only - they are derived from version banners. Distros often",
         "> back-port fixes without changing the version string. Confirm before reporting or patching.", ""]
    counts = {s: 0 for s in ORDER}
    for s in report["services"]:
        for c in s["cves"]:
            counts[c["severity"]] += 1
    L += ["## Summary", "", "| Severity | Matches |", "|---|---|"]
    L += [f"| {s} | {n} |" for s, n in counts.items() if n]
    L += ["", "## Services", "", "| Port | Product | Version | Banner |", "|---|---|---|---|"]
    for s in report["services"]:
        prods = ", ".join(f"{p['label']}" for p in s["detected"]) or "unidentified"
        vers = ", ".join(p["version"] for p in s["detected"]) or "-"
        b = (s["banner"] or "").splitlines()[0][:60].replace("|", "/") if s["banner"] else ""
        L.append(f"| {s['port']} | {prods} | {vers} | `{b}` |")
    L += ["", "## Possible CVE matches", ""]
    any_ = False
    for s in report["services"]:
        for p in s["detected"]:
            cves = [c for c in s["cves"] if c["product"] == p["label"]]
            if not cves: continue
            any_ = True
            L += [f"### {p['label']} {p['version']} (port {s['port']})", "",
                  "| CVE | CVSS | Severity | KEV | Summary | Triage |", "|---|---|---|---|---|---|"]
            for c in cves:
                L.append(f"| [{c['cve']}]({c['url']}) | {c['score']} | {c['severity']} | "
                         f"{'YES' if c['kev'] else '-'} | {c['summary'][:140].replace('|','/')} | "
                         f"{TRIAGE.get(c['severity'], 'Review')} |")
            L.append("")
    if not any_:
        L.append("No possible matches found.\n")
    L += ["## Triage & responsible disclosure notes", "",
          "1. **Validate** - confirm the real version (package manager, `-V`, vendor advisory); check back-ports.",
          "2. **Prioritise** - CVSS x exposure x exploitability (KEV = known exploited -> bump priority).",
          "3. **Fix** - patch/upgrade, or mitigate (disable feature, restrict network access, WAF rule).",
          "4. **If it is someone else's system** - do not exploit; report privately to the owner / security@ or",
          "   a bug-bounty program, give a clear description, and allow a reasonable fix window (e.g. 90 days).",
          "   See `docs/RESPONSIBLE_DISCLOSURE.md`.", ""]
    return "\n".join(L)


# -------------------------------------------------------------------- main
def parse_ports(s):
    ports = set()
    for part in s.split(","):
        if "-" in part:
            a, b = part.split("-"); ports.update(range(int(a), int(b) + 1))
        elif part.strip():
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def is_private(ip):
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_loopback or a.is_link_local


def main(argv=None):
    ap = argparse.ArgumentParser(description="Lightweight vulnerability / CVE scanner")
    ap.add_argument("target")
    ap.add_argument("-p", "--ports", default=",".join(map(str, DEFAULT_PORTS)))
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--offline", action="store_true", help="use local signature DB only (no API calls)")
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--max-cves", type=int, default=10, help="max CVEs listed per service")
    ap.add_argument("--authorized", action="store_true",
                    help="confirm you have permission to scan a non-private target")
    ap.add_argument("--report", help="write Markdown report here")
    ap.add_argument("--json", help="write JSON report here")
    a = ap.parse_args(argv)

    try:
        ip = socket.gethostbyname(a.target)
    except socket.gaierror:
        print("Cannot resolve target"); return 2
    if not is_private(ip) and not a.authorized:
        print(f"Refusing to scan public address {ip}. Re-run with --authorized ONLY if you have written permission.")
        return 2

    ports = parse_ports(a.ports)
    print(f"[*] Scanning {a.target} ({ip}) - {len(ports)} ports")
    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        banners = list(ex.map(lambda p: (p, grab_banner(ip, p, a.timeout)), ports))
    open_ports = [(p, b) for p, b in banners if b is not None]

    db, cache = load_offline_db(), {}
    services = []
    for port, banner in open_ports:
        det = detect_services(port, banner)
        cves = []
        for d in det:
            found, mode_used = [], "offline"
            if not a.offline:
                try:
                    found, mode_used = query_nvd(to_cpe(d["vendor"], d["product"], d["version"]), a.api_key, cache), "NVD"
                except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
                    print(f"[!] NVD lookup failed for {d['label']} ({e.__class__.__name__}); using offline DB")
            if not found:
                found = match_offline(db, d["vendor"], d["product"], d["version"])
            for c in found[:a.max_cves]:
                cves.append({**c, "product": d["label"]})
        print(f"[+] {port}/tcp open  {', '.join(d['label']+' '+d['version'] for d in det) or 'unidentified'}"
              f"  ({len(cves)} possible CVEs)")
        services.append(dict(port=port, banner=banner, detected=det, cves=cves))

    report = dict(target=a.target, ip=ip, date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                  mode="offline signatures" if a.offline else "NVD API (offline fallback)", services=services)
    md = render_markdown(report)
    if a.report:
        os.makedirs(os.path.dirname(os.path.abspath(a.report)), exist_ok=True)
        open(a.report, "w", encoding="utf-8").write(md); print(f"[*] Markdown report -> {a.report}")
    if a.json:
        os.makedirs(os.path.dirname(os.path.abspath(a.json)), exist_ok=True)
        json.dump(report, open(a.json, "w", encoding="utf-8"), indent=2); print(f"[*] JSON report -> {a.json}")
    if not a.report and not a.json:
        print("\n" + md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
