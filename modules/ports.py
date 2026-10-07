"""Port specification and scan-profile helpers."""

from dataclasses import dataclass


@dataclass(frozen=True)
class TimingProfile:
    level: int
    timeout: float
    workers: int
    retries: int


TIMING_PROFILES = {
    1: TimingProfile(1, 2.0, 10, 3),
    2: TimingProfile(2, 1.0, 25, 2),
    3: TimingProfile(3, 0.5, 50, 1),
    4: TimingProfile(4, 0.25, 100, 1),
    5: TimingProfile(5, 0.10, 200, 0),
}


def parse_ports(spec: str) -> list[int]:
    """Parse comma-separated ports and inclusive ranges."""
    ports: set[int] = set()

    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue

        if "-" in token:
            left, right = token.split("-", 1)
            start, end = int(left), int(right)
            if not 1 <= start <= end <= 65535:
                raise ValueError(f"Invalid port range: {token}")
            ports.update(range(start, end + 1))
        else:
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError(f"Invalid port: {token}")
            ports.add(port)

    if not ports:
        raise ValueError("No ports supplied.")

    return sorted(ports)


def timing_profile(level: int) -> TimingProfile:
    try:
        return TIMING_PROFILES[level]
    except KeyError as exc:
        raise ValueError("Timing level must be between 1 and 5.") from exc
