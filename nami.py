#!/usr/bin/env python3
"""NAMI Maps - Network Analysis & Mapping Intelligence."""

import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.discovery import discover_hosts


def parse_ports(value: str) -> list[int]:
    ports = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start, end = map(int, part.split("-", 1))
                if not (1 <= start <= end <= 65535):
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if not 1 <= port <= 65535:
                    raise ValueError
                ports.add(port)
        except ValueError:
            raise ValueError(f"Invalid port specification: {part}")
    if not ports:
        raise ValueError("No valid ports supplied.")
    return sorted(ports)


def scan_port(host: str, port: int, timeout: float):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) == 0:
            return port, "open"
        return port, None
    except (socket.timeout, OSError):
        return port, None
    finally:
        sock.close()


def scan_host(host: str, ports: list[int], timeout: float, workers: int):
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_port, host, port, timeout)
            for port in ports
        ]
        for future in as_completed(futures):
            port, state = future.result()
            if state == "open":
                open_ports.append(port)
    return sorted(open_ports)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="nami",
        description="NAMI Maps - Network Analysis & Mapping Intelligence",
    )
    parser.add_argument("target", help="IPv4 address or CIDR network")
    parser.add_argument(
        "--ports",
        default="22,80,443",
        help="Ports/ranges, e.g. 22,80,443 or 1-1024",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="TCP connection timeout in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Maximum concurrent port scans (default: 50)",
    )
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be positive.")
    if args.workers <= 0:
        parser.error("--workers must be positive.")

    try:
        network = ipaddress.ip_network(args.target, strict=False)
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    print()
    print("NAMI Maps")
    print("Network Analysis & Mapping Intelligence")
    print("Developed by Punith Kumar M G")
    print("-" * 58)
    print(f"Target  : {network}")
    print(f"Ports   : {args.ports}")
    print(f"Workers : {args.workers}")
    print("-" * 58)

    hosts = discover_hosts(network)
    if not hosts:
        print("No responsive hosts discovered.")
        return 0

    print(f"Discovered hosts: {len(hosts)}")
    print()

    for index, host in enumerate(hosts, 1):
        host_string = str(host)
        print(f"[{index}/{len(hosts)}] {host_string}")
        open_ports = scan_host(host_string, ports, args.timeout, args.workers)
        print(
            "  Open ports: "
            + (", ".join(map(str, open_ports)) if open_ports else "none")
        )
        print()

    print("Scan complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
