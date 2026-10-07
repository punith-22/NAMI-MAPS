"""Extensible NAMI scan engine.

The engine separates scheduling from protocol implementations so raw-packet
TCP/UDP/IPv6 engines can be added without changing the CLI layer.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import PortResult


class ConnectEngine:
    name = "tcp-connect"

    def scan(self, host: str, port: int, timeout: float) -> PortResult:
        started = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            code = sock.connect_ex((host, port))
            if code == 0:
                state, reason = "open", "syn-ack/connect"
            else:
                state, reason = "closed", f"connect-error:{code}"
        except socket.timeout:
            state, reason = "filtered", "timeout"
        except OSError as exc:
            state, reason = "filtered", exc.__class__.__name__
        finally:
            sock.close()

        return PortResult(
            port=port,
            protocol="tcp",
            state=state,
            reason=reason,
            latency_ms=(time.perf_counter() - started) * 1000,
        )


class UdpEngine:
    name = "udp"

    def scan(self, host: str, port: int, timeout: float) -> PortResult:
        started = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        try:
            sock.sendto(b"\x00", (host, port))
            try:
                data, _ = sock.recvfrom(2048)
                state, reason = "open", "udp-response"
                _ = data
            except socket.timeout:
                state, reason = "open|filtered", "no-response"
        except ConnectionRefusedError:
            state, reason = "closed", "icmp-port-unreachable"
        except OSError as exc:
            state, reason = "filtered", exc.__class__.__name__
        finally:
            sock.close()

        return PortResult(
            port=port,
            protocol="udp",
            state=state,
            reason=reason,
            latency_ms=(time.perf_counter() - started) * 1000,
        )


def scan_ports(
    host: str,
    ports: list[int],
    engine,
    timeout: float,
    workers: int,
) -> list[PortResult]:
    """Schedule a protocol engine across a target's ports."""
    results = []

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [
            pool.submit(engine.scan, host, port, timeout)
            for port in ports
        ]

        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda item: item.port)
