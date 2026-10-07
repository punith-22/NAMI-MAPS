#!/usr/bin/env python3
"""NAMI Maps - Network Analysis & Mapping Intelligence."""

import argparse
import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.discovery import discover_hosts
from modules.output import normal, write_json, write_xml
from modules.services import identify


TIMING = {1: (2.0, 10), 2: (1.0, 25), 3: (0.5, 50), 4: (0.25, 100), 5: (0.1, 200)}


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


def tcp_scan(host: str, port: int, timeout: float) -> dict:
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        state = "open" if sock.connect_ex((host, port)) == 0 else "closed"
    except socket.timeout:
        state = "filtered"
    except OSError:
        state = "filtered"
    finally:
        sock.close()
    return {
        "port": port, "protocol": "tcp", "state": state,
        "latency_ms": (time.perf_counter() - started) * 1000,
    }


def udp_scan(host: str, port: int, timeout: float) -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"\x00", (host, port))
        try:
            data, _ = sock.recvfrom(2048)
            state = "open" if data else "open|filtered"
        except socket.timeout:
            state = "open|filtered"
    except ConnectionRefusedError:
        state = "closed"
    except OSError:
        state = "filtered"
    finally:
        sock.close()
    return {"port": port, "protocol": "udp", "state": state}


def scan_host(host: str, ports: list[int], timeout: float, workers: int,
              udp: bool, version: bool) -> dict:
    scanner = udp_scan if udp else tcp_scan
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scanner, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result["state"] in {"open", "open|filtered"}:
                service = identify(host, result["port"], timeout) if version and not udp else {}
                result.update(service)
            if result["state"] != "closed":
                results.append(result)
    return sorted(results, key=lambda item: item["port"])


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="nami",
        description="NAMI Maps - Network Analysis & Mapping Intelligence",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="IPv4 address, CIDR network, or hostname")
    parser.add_argument("-p", "--ports", default="22,80,443", help="Ports/ranges")
    parser.add_argument("-sT", action="store_true", help="TCP connect scan")
    parser.add_argument("-sU", action="store_true", help="UDP scan")
    parser.add_argument("-sV", action="store_true", help="Probe open TCP services")
    parser.add_argument("-sn", action="store_true", help="Host discovery only")
    parser.add_argument("-Pn", action="store_true", help="Skip host discovery")
    parser.add_argument("-T", "--timing", type=int, choices=range(1, 6), default=3,
                        help="Timing profile")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-oN", metavar="FILE", help="Normal output file")
    parser.add_argument("-oJ", metavar="FILE", help="JSON output file")
    parser.add_argument("-oX", metavar="FILE", help="XML output file")
    args = parser.parse_args()

    if args.sU and args.sT:
        parser.error("choose one scan type: -sT or -sU")

    try:
        network = ipaddress.ip_network(args.target, strict=False)
    except ValueError:
        try:
            resolved = socket.gethostbyname(args.target)
            network = ipaddress.ip_network(resolved + "/32")
        except OSError as exc:
            parser.error(f"unable to resolve target: {exc}")

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    timeout, workers = TIMING[args.timing]
    udp = args.sU

    if args.Pn:
        hosts = list(network.hosts()) if network.prefixlen < 32 else [network.network_address]
    else:
        hosts = discover_hosts(network)

    results = []
    for host in hosts:
        host_string = str(host)
        started = time.perf_counter()
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(host_string)[0]
        except (socket.herror, OSError):
            pass

        record = {
            "host": host_string,
            "hostname": hostname,
            "up": True,
            "ports": [],
        }

        if not args.sn:
            record["ports"] = scan_host(
                host_string, ports, timeout, workers, udp, args.sV
            )

        record["latency_ms"] = (time.perf_counter() - started) * 1000
        results.append(record)

        if args.verbose:
            print(f"[+] {host_string} ({hostname or 'no-rDNS'})")

    if not results:
        print("No responsive hosts discovered.")
        return 0

    text = normal(results, args.verbose)
    print(text)

    if args.oN:
        with open(args.oN, "w", encoding="utf-8") as handle:
            handle.write(text)
    if args.oJ:
        write_json(results, args.oJ)
    if args.oX:
        write_xml(results, args.oX)

    return 0


if __name__ == "__main__":
    sys.exit(main())
