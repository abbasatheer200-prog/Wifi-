#!/usr/bin/env python3
"""Local-only home network audit utility. Use only on networks you own or are authorized to assess."""
from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP",
    443: "HTTPS", 445: "SMB", 554: "RTSP", 8080: "HTTP-alt", 8443: "HTTPS-alt"
}

def get_local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # This does not send application data; it determines the selected local interface.
        sock.connect(("192.0.2.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()

def infer_subnet(local_ip: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except ValueError:
        return "127.0.0.1/32"

def ping_host(ip: str, timeout: float = 1.0) -> dict:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        # macOS and Linux have different timeout flags.
        cmd = ["ping", "-c", "1", ip]
        if system == "linux":
            cmd += ["-W", str(max(1, int(timeout)))]
    start = time.perf_counter()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return {"ip": ip, "reachable": result.returncode == 0, "latency_ms": elapsed_ms if result.returncode == 0 else None}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {"ip": ip, "reachable": False, "latency_ms": None}

def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None

def check_ports(ip: str, timeout: float = 0.35) -> list[dict]:
    results = []
    for port, label in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            status = "open" if sock.connect_ex((ip, port)) == 0 else "closed_or_filtered"
        except OSError:
            status = "closed_or_filtered"
        finally:
            sock.close()
        results.append({"port": port, "service": label, "status": status})
    return results

def audit(subnet: str, include_ports: bool = False, workers: int = 32) -> dict:
    network = ipaddress.ip_network(subnet, strict=False)
    if network.version != 4:
        raise ValueError("IPv4 subnets only are supported.")
    # Prevent accidental scans of very large ranges.
    if network.num_addresses > 256:
        raise ValueError("For safety, this tool accepts at most 256 addresses per scan.")
    local_ip = get_local_ip()
    hosts = [str(ip) for ip in network.hosts()]
    devices = []
    with ThreadPoolExecutor(max_workers=min(workers, 64)) as pool:
        futures = {pool.submit(ping_host, ip): ip for ip in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result["reachable"]:
                result["hostname"] = reverse_dns(result["ip"])
                if include_ports:
                    result["ports"] = check_ports(result["ip"])
                devices.append(result)
    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "local_ip": local_ip,
        "subnet": str(network),
        "host_count_checked": len(hosts),
        "reachable_count": len(devices),
        "port_check_enabled": include_ports,
        "devices": devices,
        "notes": [
            "Ping discovery can miss devices that block ICMP.",
            "Port results are limited checks and may be affected by firewall behavior."
        ]
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Local home network inventory and basic connectivity audit.")
    parser.add_argument("--subnet", help="IPv4 subnet in CIDR format; defaults to inferred local /24.")
    parser.add_argument("--ports", action="store_true", help="Check a limited list of common TCP ports on reachable devices.")
    parser.add_argument("--output", help="Custom JSON output file.")
    args = parser.parse_args()

    local_ip = get_local_ip()
    subnet = args.subnet or infer_subnet(local_ip)
    try:
        report = audit(subnet, include_ports=args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    out_path = Path(args.output) if args.output else Path("reports") / f"audit-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Local IP: {local_ip}")
    print(f"Subnet: {report['subnet']}")
    print(f"Reachable devices: {report['reachable_count']}/{report['host_count_checked']}")
    print(f"Report saved: {out_path}")
    for device in report["devices"]:
        name = device.get("hostname") or "unknown"
        print(f"- {device['ip']} | {name} | {device['latency_ms']} ms")
    if args.ports:
        print("Limited port checks completed.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
