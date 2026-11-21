# Home Network Audit V3

A small, local-only Python utility for auditing your own home LAN. It discovers reachable hosts, checks basic connectivity, performs an optional limited TCP-port check, and saves a JSON report.

## Safety and scope
- Runs on the computer where you launch it; it does not send scans to a cloud service.
- Only scan networks you own or have explicit permission to assess.
- Host discovery uses ICMP ping where available.
- Port checks are **optional** and limited to a short list of common ports.
- No exploitation, credential guessing, packet interception, or modification of router settings.

## Requirements
- Python 3.9+
- Windows, Linux, or macOS
- For best discovery results, run on the same Wi-Fi/LAN as the router.

## Run
```bash
python network_audit.py
```

Optional limited port check:
```bash
python network_audit.py --ports
```

Specify your local subnet (example only; replace with your actual LAN):
```bash
python network_audit.py --subnet 192.168.1.0/24
```

Reports are saved under `reports/` as JSON. The tool attempts to infer your local IPv4 subnet if `--subnet` is omitted. If inference fails, specify it manually.

## Output
- Local IP and selected subnet
- Reachable IP addresses
- Reverse DNS names when available
- Basic latency estimate
- Optional limited TCP checks for common ports

## Limitations
Ping may be blocked by some devices/firewalls. A device that does not answer ping can still be connected. Port status is reported as open/closed/filtered based on a short connection timeout; results are not definitive.
