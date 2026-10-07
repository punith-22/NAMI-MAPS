"""Low-level IPv4/TCP packet primitives for NAMI Maps.

Linux raw sockets require CAP_NET_RAW/root. This module intentionally keeps
packet construction separate from scan scheduling so additional protocols
can reuse the primitives.
"""

import ipaddress
import random
import socket
import struct


def checksum(data: bytes) -> int:
    """Return the Internet checksum for an even/odd length byte sequence."""
    if len(data) % 2:
        data += b"\x00"

    total = sum(
        (data[index] << 8) + data[index + 1]
        for index in range(0, len(data), 2)
    )

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def ipv4_header(
    source: str,
    destination: str,
    payload_length: int,
    protocol: int,
    identification: int | None = None,
) -> bytes:
    """Build a minimal IPv4 header."""
    identification = (
        random.randint(0, 0xFFFF)
        if identification is None
        else identification
    )

    version_ihl = (4 << 4) | 5
    total_length = 20 + payload_length

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        identification,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(source),
        socket.inet_aton(destination),
    )

    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


def tcp_segment(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    flags: int = 0x02,
    window: int = 64240,
) -> bytes:
    """Build a TCP segment with a valid pseudo-header checksum."""
    data_offset = 5 << 4

    header = struct.pack(
        "!HHLLBBHHH",
        source_port,
        destination_port,
        sequence,
        0,
        data_offset,
        flags,
        window,
        0,
        0,
    )

    source_bytes = socket.inet_aton(source)
    destination_bytes = socket.inet_aton(destination)

    pseudo = struct.pack(
        "!4s4sBBH",
        source_bytes,
        destination_bytes,
        0,
        socket.IPPROTO_TCP,
        len(header),
    )

    value = checksum(pseudo + header)
    return header[:16] + struct.pack("!H", value) + header[18:]


def parse_ipv4_tcp(packet: bytes) -> dict | None:
    """Extract source/destination IPv4 and TCP flags from an IPv4 packet."""
    if len(packet) < 40:
        return None

    version = packet[0] >> 4
    ihl = (packet[0] & 0x0F) * 4

    if version != 4 or ihl < 20 or len(packet) < ihl + 20:
        return None

    if packet[9] != socket.IPPROTO_TCP:
        return None

    source = socket.inet_ntoa(packet[12:16])
    destination = socket.inet_ntoa(packet[16:20])

    tcp = packet[ihl:]
    source_port, destination_port = struct.unpack("!HH", tcp[:4])

    sequence = struct.unpack("!L", tcp[4:8])[0]
    acknowledgment = struct.unpack("!L", tcp[8:12])[0]

    flags = tcp[13]

    return {
        "source": source,
        "destination": destination,
        "source_port": source_port,
        "destination_port": destination_port,
        "sequence": sequence,
        "acknowledgment": acknowledgment,
        "flags": flags,
        "syn": bool(flags & 0x02),
        "ack": bool(flags & 0x10),
        "rst": bool(flags & 0x04),
        "fin": bool(flags & 0x01),
    }


def local_ipv4(destination: str) -> str:
    """Determine the local IPv4 address used to reach a destination."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((str(ipaddress.ip_address(destination)), 53))
        return sock.getsockname()[0]
    finally:
        sock.close()
