"""ICMP host discovery for NAMI Maps."""

import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


def _ping(host: ipaddress.IPv4Address) -> bool:
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", "1000", str(host)]
    else:
        command = ["ping", "-c", "1", "-W", "1", str(host)]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def discover_hosts(
    network: ipaddress.IPv4Network,
    workers: int = 64,
) -> list[ipaddress.IPv4Address]:
    candidates = (
        [network.network_address]
        if network.prefixlen == 32
        else list(network.hosts())
    )
    if not candidates:
        return []

    found = []
    with ThreadPoolExecutor(max_workers=min(workers, len(candidates))) as executor:
        futures = {executor.submit(_ping, host): host for host in candidates}
        for future in as_completed(futures):
            host = futures[future]
            if future.result():
                found.append(host)
    return sorted(found)
