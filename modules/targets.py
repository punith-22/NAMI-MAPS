"""Target normalization for NAMI Maps."""

import ipaddress
import socket


def resolve_target(value: str) -> list[ipaddress.IPv4Network]:
    """Resolve an IPv4/CIDR/hostname into normalized IPv4 networks."""
    try:
        return [ipaddress.ip_network(value, strict=False)]
    except ValueError:
        pass

    try:
        addresses = sorted({socket.gethostbyname(value)})
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target: {value}") from exc

    return [ipaddress.ip_network(f"{address}/32") for address in addresses]


def hosts(network: ipaddress.IPv4Network):
    if network.prefixlen == 32:
        yield network.network_address
        return

    yield from network.hosts()
