"""TCP SYN scanning engine for NAMI Maps.

This engine is intended for authorized networks. It uses an IPv4 raw packet
socket and therefore normally requires root/CAP_NET_RAW on Linux.
"""

import os
import random
import socket
import time

from .models import PortResult
from .packet import local_ipv4, parse_ipv4_tcp, tcp_segment


class RawSocketUnavailable(RuntimeError):
    """Raised when the operating system refuses raw packet access."""


class SynEngine:
    name = "tcp-syn"

    def __init__(self, host: str, timeout: float = 0.5, retries: int = 1):
        self.host = host
        self.timeout = timeout
        self.retries = max(0, retries)
        self.source_ip = local_ipv4(host)
        self.source_port = random.randint(32768, 60999)
        self.socket = None

    @staticmethod
    def available() -> bool:
        if os.name != "posix":
            return False

        try:
            probe = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_TCP,
            )
            probe.close()
            return True
        except OSError:
            return False

    def __enter__(self):
        try:
            self.socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_TCP,
            )
            self.socket.settimeout(self.timeout)
        except OSError as exc:
            raise RawSocketUnavailable(
                "Raw TCP access unavailable; run with CAP_NET_RAW/root "
                "or use TCP connect scanning."
            ) from exc
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.socket:
            self.socket.close()
            self.socket = None

    def scan(self, port: int) -> PortResult:
        if self.socket is None:
            raise RuntimeError("SynEngine must be used as a context manager.")

        started = time.perf_counter()
        sequence = random.randint(0, 0xFFFFFFFF)

        segment = tcp_segment(
            self.source_ip,
            self.host,
            self.source_port,
            port,
            sequence,
            flags=0x02,
        )

        for attempt in range(self.retries + 1):
            try:
                self.socket.sendto(segment, (self.host, 0))
            except OSError as exc:
                return PortResult(
                    port=port,
                    protocol="tcp",
                    state="filtered",
                    reason=f"send-error:{exc.__class__.__name__}",
                )

            deadline = time.monotonic() + self.timeout

            while time.monotonic() < deadline:
                try:
                    packet, _ = self.socket.recvfrom(65535)
                except socket.timeout:
                    break

                parsed = parse_ipv4_tcp(packet)
                if not parsed:
                    continue

                if (
                    parsed["source"] != self.host
                    or parsed["source_port"] != port
                    or parsed["destination_port"] != self.source_port
                ):
                    continue

                if parsed["syn"] and parsed["ack"]:
                    return PortResult(
                        port=port,
                        protocol="tcp",
                        state="open",
                        reason="syn-ack",
                        latency_ms=(time.perf_counter() - started) * 1000,
                    )

                if parsed["rst"]:
                    return PortResult(
                        port=port,
                        protocol="tcp",
                        state="closed",
                        reason="rst",
                        latency_ms=(time.perf_counter() - started) * 1000,
                    )

            if attempt < self.retries:
                continue

        return PortResult(
            port=port,
            protocol="tcp",
            state="filtered",
            reason="no-response",
            latency_ms=(time.perf_counter() - started) * 1000,
        )
