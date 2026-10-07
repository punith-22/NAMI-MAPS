# NAMI Maps

**Network Analysis & Mapping Intelligence**

NAMI Maps is a native, modular CLI network scanner designed to grow toward Nmap-class network discovery and security auditing capabilities.

**Developed by Punith Kumar M G**

> Use NAMI Maps only against systems and networks you own or are explicitly authorized to assess.

## Current Engine

The project has moved beyond the original proof-of-concept scanner.

### Implemented

- IPv4 target and CIDR parsing
- Hostname resolution
- ICMP-based host discovery
- `-sn` host-discovery-only mode
- `-Pn` skip-discovery mode
- TCP connect scanning
- UDP scanning
- Port lists and ranges with `-p`
- Timing profiles `-T1` through `-T5`
- Concurrent scanning
- Reverse DNS
- Service identification with `-sV`
- HTTP/HTTPS probing
- SSH/FTP/SMTP banner recognition
- Normal output
- JSON output with `-oJ`
- XML output with `-oX`
- Normal file output with `-oN`
- Verbose mode with `-v`
- Standard-library runtime

## Examples

### TCP scan

```bash
python3 nami.py -sT -p 22,80,443 192.168.1.10
```

### Host discovery

```bash
python3 nami.py -sn 192.168.1.0/24
```

### Skip discovery

```bash
python3 nami.py -Pn -p 1-1024 192.168.1.10
```

### Service detection

```bash
python3 nami.py -sT -sV -p 22,80,443 192.168.1.10
```

### UDP

```bash
python3 nami.py -sU -p 53,123,161 192.168.1.10
```

### Faster timing profile

```bash
python3 nami.py -sT -T4 -p 1-1024 192.168.1.10
```

### JSON report

```bash
python3 nami.py -sT -sV -p 22,80,443 -oJ scan.json 192.168.1.10
```

### XML report

```bash
python3 nami.py -sT -sV -p 22,80,443 -oX scan.xml 192.168.1.10
```

## Architecture

```text
NAMI-MAPS/
├── nami.py                  # CLI and scan orchestration
├── modules/
│   ├── __init__.py
│   ├── discovery.py         # Host discovery
│   ├── services.py          # Service/version probes
│   └── output.py            # Normal/JSON/XML output
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

## Roadmap to NAMI 1.0

### Phase 1 — Scanning Engine
- TCP SYN scanning
- Improved TCP state classification
- Full UDP probe engine
- IPv6
- ARP/Neighbor Discovery
- ICMPv6
- SCTP support
- Adaptive retransmission and congestion control

### Phase 2 — Fingerprinting
- Large service-probe database
- Application/version matching
- TLS/SSL fingerprinting
- HTTP technology detection
- CPE generation
- MAC vendor identification
- TCP/IP OS fingerprinting
- Device classification

### Phase 3 — Intelligence
- DNS intelligence
- Network topology mapping
- Traceroute
- Asset inventory
- Host/service correlation
- Scan history and diffing
- Risk scoring
- Exposure summaries

### Phase 4 — Script Engine
- Native NAMI plugin system
- Safe discovery scripts
- Service-specific enumeration
- Custom user probes
- Script categories and metadata
- Sandboxed execution model

### Phase 5 — Output & Automation
- JSON, XML, CSV, NDJSON
- HTML reports
- Machine-readable API mode
- Streaming output
- Scan resume/checkpoints
- Configuration profiles
- CI/CD integration

### Phase 6 — Futuristic NAMI
- Adaptive scan planning
- Intelligent probe selection
- Distributed scanning workers
- Passive + active asset correlation
- Baseline comparison
- Anomaly detection
- Network graph generation
- Optional AI-assisted result summarization

## Design Principle

NAMI should not become a collection of random scanning scripts. The long-term architecture is:

```text
Target Parser
     ↓
Discovery Engine
     ↓
Scan Scheduler
     ↓
Protocol Engines
     ├── TCP
     ├── UDP
     ├── ICMP
     ├── IPv6
     └── ARP/ND
     ↓
Fingerprint Engine
     ├── Services
     ├── TLS
     ├── OS
     └── Device
     ↓
Intelligence Engine
     ↓
Output / Reporting / API
```

Each layer should remain independently testable and replaceable.

## Responsible Use

NAMI Maps is intended for authorized security testing, education, research, and defensive network administration.

Only scan systems and networks where you have explicit permission.

## License

MIT License.
