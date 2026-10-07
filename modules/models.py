"""Core data models for NAMI Maps."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    reason: str = ""
    latency_ms: Optional[float] = None
    banner: str = ""


@dataclass
class HostResult:
    address: str
    hostname: str = ""
    state: str = "unknown"
    reason: str = ""
    latency_ms: Optional[float] = None
    ports: list[PortResult] = field(default_factory=list)


@dataclass
class ScanConfig:
    targets: list[str]
    ports: list[int]
    scan_type: str = "connect"
    udp: bool = False
    service_detection: bool = False
    host_discovery: bool = True
    timing: int = 3
    workers: int = 50
    timeout: float = 0.5
