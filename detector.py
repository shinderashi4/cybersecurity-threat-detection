#!/usr/bin/env python3
"""Security Hunter - log parsing, threat hunting and incident-response helper.
Usage: python detector.py [--log FILE] [--out DIR] [--threshold 5] [--window 60]
With no --log it generates a simulated log so it always runs end-to-end.
"""
import argparse, json, os, re, random
from collections import defaultdict, deque
from datetime import datetime, timedelta

# ---------- Regex parsers ----------
ACCESS_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<uri>\S+) [^"]*" (?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"')
SSH_FAIL_RE = re.compile(
    r'(?P<ts>[A-Z][a-z]{2} +\d+ \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: Failed password for '
    r'(?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})')

ATTACK_PATTERNS = {
    "Directory Traversal": re.compile(r'(\.\./|%2e%2e%2f|\.\.\\)', re.I),
    "SQL Injection": re.compile(r'(union(\s|%20|\+)+select|or(\s|%20|\+)+1=1|sleep\(\d+\)|\'--)', re.I),
    "Web Shell / RCE": re.compile(r'(eval\(|base64_decode|cmd=|/bin/sh|wget(\s|%20)http)', re.I),
}
BAD_UA = re.compile(r'(sqlmap|nikto|nmap|hydra|masscan)', re.I)

# Simulated threat-intel blocklist (documentation-range IPs)
BLOCKLIST = {"203.0.113.50", "198.51.100.23", "192.0.2.99"}

def parse_ts(s):
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S"):
        try:
            d = datetime.strptime(s.strip(), fmt)
            return d.replace(year=datetime.now().year) if fmt == "%b %d %H:%M:%S" else d.replace(tzinfo=None)
        except ValueError:
            continue
    return datetime.now()

def parse_line(line):
    m = SSH_FAIL_RE.search(line)
    if m:
        return {"type": "ssh_fail", "ip": m["ip"], "ts": parse_ts(m["ts"]), "user": m["user"], "raw": line.strip()}
    m = ACCESS_RE.search(line)
    if m:
        return {"type": "web", "ip": m["ip"], "ts": parse_ts(m["ts"]), "uri": m["uri"],
                "status": int(m["status"]), "ua": m["ua"], "raw": line.strip()}
    return None

# ---------- Detection ----------
def detect(events, threshold=5, window=60):
    alerts, recent = [], defaultdict(deque)
    flagged = set()
    for e in events:
        ip = e["ip"]
        failed = e["type"] == "ssh_fail" or (e["type"] == "web" and e["status"] in (401, 403))
        if failed:  # sliding-window brute force
            q = recent[ip]
            q.append(e["ts"])
            while q and (e["ts"] - q[0]).total_seconds() > window:
                q.popleft()
            if len(q) >= threshold and ("BF", ip) not in flagged:
                flagged.add(("BF", ip))
                alerts.append(mk(ip, "Brute Force", f"{len(q)} failures in {window}s", e, 6))
        if e["type"] == "web":  # web attack heuristics
            for name, rx in ATTACK_PATTERNS.items():
                if rx.search(e["uri"]):
                    alerts.append(mk(ip, name, e["uri"], e, 1))
            if BAD_UA.search(e["ua"]):
                alerts.append(mk(ip, "Scanner User-Agent", e["ua"], e, 1))
        if ip in BLOCKLIST and ("IOC", ip) not in flagged:  # IoC matching
            flagged.add(("IOC", ip))
            alerts.append(mk(ip, "IoC Blocklist Match", "IP in threat-intel feed", e, 6))
    return alerts

def mk(ip, kind, detail, e, weight):
    return {"ip": ip, "type": kind, "detail": detail, "time": e["ts"].isoformat(), "weight": weight, "raw": e["raw"]}

def triage(ip_alerts):
    score = sum(a["weight"] for a in ip_alerts) + len({a["type"] for a in ip_alerts})
    return "Critical" if score >= 12 else "High" if score >= 7 else "Medium" if score >= 3 else "Low"

def respond(alerts, outdir):
    by_ip = defaultdict(list)
    for a in alerts:
        by_ip[a["ip"]].append(a)
    report = []
    for ip, al in by_ip.items():
        report.append({"ip": ip, "severity": triage(al), "alerts": len(al),
                       "types": sorted({a["type"] for a in al}),
                       "remediation": f"iptables -A INPUT -s {ip} -j DROP"})
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    report.sort(key=lambda r: order[r["severity"]])
    os.makedirs(outdir, exist_ok=True)  # evidence preservation
    with open(os.path.join(outdir, "incident_report.json"), "w") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(outdir, "evidence.log"), "w") as f:
        f.writelines(a["raw"] + "\n" for a in alerts)
    return report

# ---------- Simulated log ----------
def simulate():
    t, lines, r = datetime(2026, 11, 3, 10, 0, 0), [], random.Random(7)
    def web(ip, uri, st, ua="Mozilla/5.0", off=0):
        ts = (t + timedelta(seconds=off)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        return f'{ip} - - [{ts}] "GET {uri} HTTP/1.1" {st} 512 "-" "{ua}"'
    for i in range(20):
        lines.append(web(f"10.0.0.{r.randint(2,9)}", r.choice(["/", "/about", "/products"]), 200, off=i * 5))
    for i in range(8):
        lines.append(web("198.51.100.77", "/login", 401, off=100 + i * 3))
    for i in range(7):
        ts = (t + timedelta(seconds=200 + i * 4)).strftime("%b %d %H:%M:%S")
        lines.append(f"{ts} srv sshd[1{i}]: Failed password for invalid user admin from 192.0.2.10 port 22 ssh2")
    lines += [web("203.0.113.8", "/../../etc/passwd", 404, off=300),
              web("203.0.113.8", "/items?id=1%20UNION%20SELECT%20user,pass%20FROM%20users", 200, off=301),
              web("203.0.113.8", "/s.php?cmd=base64_decode(abc)", 200, "sqlmap/1.7", off=302),
              web("203.0.113.50", "/", 200, off=310)]
    return lines

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log")
    p.add_argument("--out", default="evidence")
    p.add_argument("--threshold", type=int, default=5)
    p.add_argument("--window", type=int, default=60)
    a = p.parse_args()
    lines = open(a.log, errors="ignore").read().splitlines() if a.log else simulate()
    events = sorted(filter(None, map(parse_line, lines)), key=lambda e: e["ts"])
    print(f"[*] Parsed {len(events)} events from {len(lines)} lines")
    alerts = detect(events, a.threshold, a.window)
    report = respond(alerts, a.out)
    print(f"[!] {len(alerts)} alerts across {len(report)} source IPs\n")
    for r in report:
        print(f"[{r['severity'].upper():8}] {r['ip']:16} {', '.join(r['types'])}\n           -> {r['remediation']}")
    print(f"\n[+] Evidence saved to ./{a.out}/")

if __name__ == "__main__":
    main()