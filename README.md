# NetProbe — Production-Quality Authorized Security Assessment Tool

NetProbe is a modular, high-performance network reconnaissance and port scanning tool written in Python. It is designed as an educational, interview-quality alternative to Nmap's port discovery and service detection capabilities.

> [!CAUTION]
> **LEGAL & ETHICAL DISCLAIMER**  
> This software is intended solely for use against systems and networks that you own or are explicitly authorized to assess. Unauthorized scanning may violate laws, regulations, organizational policies, or contractual agreements. The user is solely responsible for ensuring they have permission before running this tool.

---

## Key Features

- **Asynchronous Engine**: Leverages Python `asyncio` for highly concurrent, non-blocking network socket operations.
- **Multiple Scan Techniques**:
  - **TCP Connect Scan**: Clean, fallback-free mode utilizing standard sockets without requiring elevated privileges.
  - **TCP SYN Scan (Half-Open)**: Fast, stealthy scan using `scapy` with automatic privilege detection and graceful fallback.
  - **UDP Scan**: Connectionless scanning with protocol-aware probes (DNS query, NTP request, SNMP sysDescr probe, etc.) and ICMP Unreachable detection.
- **Data-Driven Service & Version Detection**:
  - Structured YAML database (`scanner/data/fingerprints.yaml`) for clean signature management.
  - Four-stage identification pipeline: NULL banner probe &rarr; protocol-specific probes &rarr; TLS certificate inspection &rarr; port heuristic guess.
  - Regex capture group extraction and confidence-ranked scoring.
- **TLS Certificate Inspection**: Automatic extraction of certificate subject, issuer, SANs, TLS version, and cipher suite for active TLS ports.
- **Performance Control**:
  - **Rate Limiting**: Enforces max packets/connections per second using a token bucket rate limiter.
  - **Adaptive Timing (T0–T5)**: Dynamically adjusts timeouts using an RFC 6298 smoothed RTT (SRTT) algorithm to match network latency.
- **Premium Reporting**: Generates human-readable terminal tables, CSVs, JSON, and beautiful glassmorphic dark-mode HTML reports.

---

## Project Structure

```text
PortScanner/
├── scanner/
│   ├── __init__.py              # Package metadata and version info
│   ├── __main__.py              # Package executable entry point
│   ├── cli.py                   # Command-line interface and target validation
│   ├── core.py                  # Core async scan orchestrator
│   ├── models.py                # Dataclasses and enums
│   ├── timing.py                # Timing profiles and adaptive RTT logic
│   │
│   ├── scanners/
│   │   ├── __init__.py          # BaseScanner ABC
│   │   ├── tcp.py               # TCP Connect & SYN scanners
│   │   └── udp.py               # UDP protocol-aware scanner
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   ├── detector.py          # Service detection orchestrator
│   │   ├── fingerprints.py      # Fingerprint database parser and regex matcher
│   │   └── tls_inspector.py     # TLS certificate inspector
│   │
│   ├── output/
│   │   ├── __init__.py
│   │   ├── table.py             # Rich console table formatter
│   │   ├── json_output.py       # JSON export formatter
│   │   ├── csv_output.py        # CSV export formatter
│   │   └── html_output.py       # Standalone dark-mode HTML report generator
│   │
│   └── data/
│       └── fingerprints.yaml    # Service probe fingerprint database
│
├── tests/
│   ├── test_models.py
│   ├── test_ports.py
│   ├── test_targets.py
│   ├── test_fingerprints.py
│   ├── test_tcp_scanner.py
│   ├── test_udp_scanner.py
│   └── test_output.py
│
├── requirements.txt             # Project runtime dependencies
└── pyproject.toml               # Build system configurations
```

---

## Installation & Setup

1. **Prerequisites**: Python 3.11+ is required.
2. **Install with uv** (recommended for speed and clean environment management):
   ```bash
   # Install dependencies in editable mode
   uv pip install -e .
   ```
3. **Alternatively, install via standard pip**:
   ```bash
   pip install -r requirements.txt
   ```

*Note on TCP SYN Scanning*: If you plan to use SYN scanning (`-sS`), `scapy` requires Raw Socket access. Run the terminal as root/Administrator:
- On Linux/macOS: Run with `sudo`
- On Windows: Install Npcap (or WinPcap) and run the command in an elevated PowerShell/CMD session.

---

## Usage Guide

Run NetProbe using Python module syntax:
```bash
python -m scanner <targets> [options]
```

### 1. Target Selection
NetProbe accepts hostnames, single IPs, CIDR ranges, and files containing targets.
```bash
# Scan single IP
python -m scanner 192.168.1.5

# Scan hostname
python -m scanner scanme.nmap.org

# Scan CIDR subnet range
python -m scanner 10.0.0.0/24

# Scan targets from a file
python -m scanner -iL targets.txt
```

### 2. Port Selection
Specify ports by number, range, list, or top common count.
```bash
# Custom list of ports
python -m scanner 192.168.1.1 -p 22,80,443

# Port ranges
python -m scanner 192.168.1.1 -p 1-1024

# Top common ports (e.g. top 50 common ports)
python -m scanner 192.168.1.1 --top-ports 50
```

### 3. Scan Techniques
```bash
# TCP Connect Scan (Default)
python -m scanner 192.168.1.1 -sT

# TCP SYN Scan (Stealth / Half-open - requires elevated privileges)
python -m scanner 192.168.1.1 -sS

# UDP Scan (Protocol-aware)
python -m scanner 192.168.1.1 -sU
```

### 4. Service Versioning & TLS Inspection
```bash
# Enable Service & Version detection
python -m scanner 192.168.1.1 -sV

# Enable Service detection + TLS Certificate analysis
python -m scanner 192.168.1.1 -sV --tls-info
```

### 5. Timing Profiles (T0–T5)
Choose timing profile ranging from T0 (slow, paranoid) to T5 (fast, CTF-insane). Default is T3.
```bash
python -m scanner 192.168.1.1 -T4
```

### 6. Output Export
Generate multiple report formats simultaneously.
```bash
python -m scanner 192.168.1.1 -p 1-1000 -sV -oN report.txt -oJ report.json -oC report.csv -oH report.html
```

---

## Performance Tuning
To limit connection rates on fragile networks, specify rate limit (max connections/second):
```bash
# Limit to 50 connections/probes per second
python -m scanner 192.168.1.1 --rate-limit 50
```

---

## Development & Test suite
NetProbe includes a complete pytest unit test suite that executes completely locally without generating live network traffic.
```bash
# Install development dependencies
uv pip install -e .[dev]

# Run all unit tests
uv run pytest -v -W error
```
