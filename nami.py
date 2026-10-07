#!/usr/bin/env python3
"""NAMI Maps - Network Analysis & Mapping Intelligence."""

import argparse
import socket
import sys
import time

from modules.discovery import discover_hosts
from modules.engine import ConnectEngine, UdpEngine, scan_ports
from modules.models import HostResult
from modules.output import normal, write_json, write_xml
from modules.ports import parse_ports, timing_profile
from modules.services import identify
from modules.syn import RawSocketUnavailable, SynEngine
from modules.targets import hosts, resolve_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nami",
        description="NAMI Maps - Network Analysis & Mapping Intelligence",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="IPv4 address, CIDR network, or hostname")
    parser.add_argument("-p", "--ports", default="22,80,443", help="Ports/ranges")
    parser.add_argument("-sS", action="store_true", help="TCP SYN scan (raw packet)")
    parser.add_argument("-sT", action="store_true", help="TCP connect scan")
    parser.add_argument("-sU", action="store_true", help="UDP scan")
    parser.add_argument("-sV", action="store_true", help="Probe open TCP services")
    parser.add_argument("-sn", action="store_true", help="Host discovery only")
    parser.add_argument("-Pn", action="store_true", help="Skip host discovery")
    parser.add_argument("-T", "--timing", type=int, choices=range(1, 6), default=3)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-oN", metavar="FILE", help="Normal output file")
    parser.add_argument("-oJ", metavar="FILE", help="JSON output file")
    parser.add_argument("-oX", metavar="FILE", help="XML output file")
    return parser


def scan_target(address, ports, args, timeout, workers, retries):
    started = time.perf_counter()

    try:
        hostname = socket.gethostbyaddr(address)[0]
    except (socket.herror, OSError):
        hostname = ""

    host = HostResult(address=address, hostname=hostname, state="up")

    if args.sn:
        host.reason = "host-discovery"
    elif args.sS:
        try:
            with SynEngine(address, timeout, retries) as engine:
                host.ports = sorted(
                    [engine.scan(port) for port in ports],
                    key=lambda result: result.port,
                )
        except (RawSocketUnavailable, OSError) as exc:
            if args.verbose:
                print(
                    f"[!] SYN engine unavailable for {address}: {exc}; "
                    "falling back to TCP connect."
                )
            host.ports = scan_ports(
                address, ports, ConnectEngine(), timeout, workers
            )
            host.reason = "tcp-connect-fallback"
    elif args.sU:
        host.ports = scan_ports(
            address, ports, UdpEngine(), timeout, workers
        )
    else:
        host.ports = scan_ports(
            address, ports, ConnectEngine(), timeout, workers
        )

    if args.sV and not args.sU:
        for result in host.ports:
            if result.state == "open":
                result.__dict__.update(identify(address, result.port, timeout))

    host.latency_ms = (time.perf_counter() - started) * 1000
    return host


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    selected = sum((args.sS, args.sT, args.sU))
    if selected > 1:
        parser.error("choose only one of -sS, -sT, or -sU")
    if not selected:
        args.sT = True

    try:
        ports = parse_ports(args.ports)
        profile = timing_profile(args.timing)
        networks = []
        for target in args.target.split(","):
            networks.extend(resolve_target(target.strip()))
    except ValueError as exc:
        parser.error(str(exc))

    discovered = []
    for network in networks:
        if args.Pn:
            discovered.extend(hosts(network))
        else:
            discovered.extend(discover_hosts(network))

    if not discovered:
        print("No responsive hosts discovered.")
        return 0

    results = []
    for address in discovered:
        record = scan_target(
            str(address),
            ports,
            args,
            profile.timeout,
            profile.workers,
            profile.retries,
        )
        results.append(record)

        if args.verbose:
            print(
                f"[+] {record.address} "
                f"({record.hostname or 'no-rDNS'}) "
                f"{len(record.ports)} result(s)"
            )

    serializable = [
        {
            "host": item.address,
            "hostname": item.hostname,
            "state": item.state,
            "reason": item.reason,
            "latency_ms": item.latency_ms,
            "ports": [port.__dict__ for port in item.ports],
        }
        for item in results
    ]

    text = normal(serializable, args.verbose)
    print(text)

    if args.oN:
        with open(args.oN, "w", encoding="utf-8") as handle:
            handle.write(text)
    if args.oJ:
        write_json(serializable, args.oJ)
    if args.oX:
        write_xml(serializable, args.oX)

    return 0


if __name__ == "__main__":
    sys.exit(main())
