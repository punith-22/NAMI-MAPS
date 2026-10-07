# NAMI Maps

**Network Analysis & Mapping Intelligence**

A pure CLI-based network scanner for authorized security testing, labs, and networks you own or have permission to assess.

**Developed by Punith Kumar M G**

## v0.1

- IPv4/CIDR target input
- ICMP host discovery
- TCP connect port scanning
- Custom ports and ranges
- Concurrent scanning
- Clean terminal output
- Python standard library only

## Requirements

- Python 3.10+
- Linux, macOS, or Windows
- Permission to scan the target

No third-party Python packages are required.

## Usage

```bash
python3 nami.py 192.168.1.0/24
python3 nami.py 192.168.1.10 --ports 22,80,443
python3 nami.py 192.168.1.10 --ports 1-1024
python3 nami.py 192.168.1.10 --ports 22,80,443 --timeout 0.8 --workers 100
```

## Project Structure

```text
NAMI-MAPS/
├── nami.py
├── modules/
│   ├── __init__.py
│   └── discovery.py
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

## Roadmap

### v0.2
- Service identification
- Banner collection
- Better progress display
- Improved timeout handling

### v0.3
- OS fingerprinting
- JSON output
- CSV reporting
- Scan profiles

### Future
- Network topology mapping
- Defensive asset analysis
- Plugin architecture
- Optional Nmap integration

## Responsible Use

NAMI Maps is intended for authorized security testing, education, and defensive network administration.

Only scan systems and networks where you have explicit permission.

## License

MIT License.
