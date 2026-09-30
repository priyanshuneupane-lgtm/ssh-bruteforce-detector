#!/usr/bin/env python3
"""SSH Brute-Force Detector: scans an sshd auth log for brute-force behaviour."""
import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta

IP = r"(?P<ip>[\da-fA-F.:]+)"
PREFIX = r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
FAILED = re.compile(PREFIX + r"Failed \w+ for (?:invalid user )?(?P<user>\S+) from " + IP)
ACCEPTED = re.compile(PREFIX + r"Accepted \w+ for (?P<user>\S+) from " + IP)


def parse_time(ts, year):
    return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")


def parse_log(lines, year):
    """Return (failures, successes): dicts/lists of parsed events."""
    failures = defaultdict(list)  # ip -> [(time, user)]
    successes = []                # [(time, ip, user)]
    for line in lines:
        m = FAILED.match(line)
        if m:
            failures[m["ip"]].append((parse_time(m["ts"], year), m["user"]))
            continue
        m = ACCEPTED.match(line)
        if m:
            successes.append((parse_time(m["ts"], year), m["ip"], m["user"]))
    return failures, successes


def max_in_window(times, window):
    """Largest number of events inside any sliding window (times must be sorted)."""
    best, start = 0, 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def analyze(lines, year=None, threshold=5, window_minutes=5):
    year = year or datetime.now().year
    window = timedelta(minutes=window_minutes)
    failures, successes = parse_log(lines, year)
    findings = []
    for ip, events in failures.items():
        events.sort()
        times = [t for t, _ in events]
        burst = max_in_window(times, window)
        if burst < threshold:
            continue
        users = sorted({u for _, u in events})
        compromised = [s for s in successes if s[1] == ip and s[0] >= times[0]]
        findings.append({
            "ip": ip,
            "total_failures": len(events),
            "peak_failures_in_window": burst,
            "usernames_tried": users,
            "first_seen": times[0].isoformat(),
            "last_seen": times[-1].isoformat(),
            "severity": "CRITICAL" if compromised else "HIGH",
            "successful_login_after_failures": [
                {"time": t.isoformat(), "user": u} for t, _, u in compromised
            ],
        })
    findings.sort(key=lambda f: (f["severity"] != "CRITICAL", -f["total_failures"]))
    return findings


def print_report(findings, threshold, window_minutes):
    print(f"SSH Brute-Force Report (>= {threshold} failures in {window_minutes} min)")
    print("=" * 60)
    if not findings:
        print("No suspicious IPs found.")
        return
    for f in findings:
        print(f"[{f['severity']}] {f['ip']}")
        print(f"  failures: {f['total_failures']} (peak {f['peak_failures_in_window']} in window)")
        print(f"  users tried: {', '.join(f['usernames_tried'])}")
        print(f"  active: {f['first_seen']} -> {f['last_seen']}")
        for s in f["successful_login_after_failures"]:
            print(f"  !! successful login as '{s['user']}' at {s['time']} - investigate")
        print()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("logfile", help="path to auth.log style file")
    p.add_argument("--threshold", type=int, default=5, help="failures needed to flag an IP")
    p.add_argument("--window", type=int, default=5, help="window size in minutes")
    p.add_argument("--year", type=int, help="log year (syslog omits it); default: current")
    p.add_argument("--json", action="store_true", help="output JSON instead of text")
    a = p.parse_args()
    with open(a.logfile, encoding="utf-8", errors="replace") as fh:
        findings = analyze(fh, a.year, a.threshold, a.window)
    if a.json:
        print(json.dumps(findings, indent=2))
    else:
        print_report(findings, a.threshold, a.window)


if __name__ == "__main__":
    main()
