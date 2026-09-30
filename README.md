# SSH Brute-Force Detector

A small Python tool that scans Linux `sshd` authentication logs and flags IP addresses
showing brute-force behaviour. It also escalates to **CRITICAL** when an IP that failed
repeatedly later logs in successfully, a common sign of a compromised account.

## Features
- Parses `Failed password` / `Accepted password` events (including invalid users)
- Sliding-window detection: N failures within M minutes (both configurable)
- Severity levels (HIGH / CRITICAL) and list of usernames targeted
- Text report or JSON output for piping into other tools
- Zero dependencies (Python 3.8+ standard library), with unit tests

## Usage
```bash
python detector.py sample_logs/auth.log --year 2026
python detector.py /var/log/auth.log --threshold 8 --window 10 --json
python -m unittest discover tests
```

## Sample output
```
[CRITICAL] 198.51.100.7
  failures: 6 (peak 6 in window)
  users tried: deploy
  !! successful login as 'deploy' at 2026-09-29T03:01:40 - investigate
```

## How it works
1. Regexes extract timestamp, username and source IP from each sshd line.
2. Failures are grouped per IP and sorted by time.
3. A two-pointer sliding window finds the peak failure count in any M-minute span.
4. IPs at or above the threshold are flagged; later successful logins raise severity.

## Ideas for extension
- Add GeoIP lookup, or auto-generate `iptables`/`fail2ban` block lists
- Detect password spraying (many users, few attempts each)
- Support `journalctl` output and `Failed publickey` events

## Disclaimer
Sample data uses fictional IPs from documentation ranges (RFC 5737). For defensive and
educational use on systems you own or are authorized to monitor.
