# NetProbe

A modular, async-first port scanner and service fingerprinting tool, written in Python. Built as an Nmap-style project to demonstrate real scan engineering — not just "connect and print" — covering TCP/UDP scanning, service/version detection, and proper reporting.

> [!CAUTION]
> **Use this only on systems you own or have explicit written permission to test.** Scanning networks you don't have authorization for can be illegal depending on your jurisdiction and is a breach of most acceptable-use policies. That responsibility is on you, not this tool.

---

## What it does

- **TCP Connect scan** — the default. Plain sockets, no special privileges needed.
- **TCP SYN scan (`-sS`)** — half-open scanning via `scapy`. Needs raw socket access (root / `CAP_NET_RAW`), and falls back to connect scan automatically if it doesn't have it.
- **UDP scan (`-sU`)** — sends protocol-aware probes (DNS query, NTP request, SNMP sysDescr, etc.) and works out open / open|filtered / closed based on responses vs. ICMP unreachable vs. timeout.
- **Service & version detection (`-sV`)** — a four-stage pipeline: try a null banner grab first, then protocol-specific probes (HTTP, SMTP EHLO, MySQL handshake, RDP negotiation, SMB, etc.), then TLS cert inspection if relevant, and fall back to a port-based guess if nothing else matches. Signatures live in a YAML file (`scanner/data/fingerprints.yaml`) so adding a new one doesn't mean touching the code.
- **TLS inspection (`--tls-info`)** — pulls cert subject/issuer/SANs plus the negotiated TLS version and cipher for anything speaking TLS.
- **Rate limiting** — token-bucket limiter so you don't hammer a target or your own NIC.
- **Adaptive timing (T0–T5)** — timeout tightens or loosens based on observed RTT instead of one fixed value for every host, loosely modeled on Nmap's timing templates.
- **Output** — terminal table, JSON, CSV, and an HTML report, all from the same scan.

## Layout

```text
PortScanner/
├── scanner/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                   # argument parsing, target validation
│   ├── core.py                  # scan orchestration (async)
│   ├── models.py                # dataclasses / enums shared across modules
│   ├── timing.py                # timing templates + adaptive RTT
│   │
│   ├── scanners/
│   │   ├── __init__.py          # BaseScanner ABC
│   │   ├── tcp.py               # connect + SYN scan
│   │   └── udp.py
│   │
│   ├── services/
│   │   ├── detector.py          # ties the probes + fingerprints together
│   │   ├── fingerprints.py      # loads and matches the YAML signature db
│   │   └── tls_inspector.py
│   │
│   ├── output/
│   │   ├── table.py
│   │   ├── json_output.py
│   │   ├── csv_output.py
│   │   └── html_output.py
│   │
│   └── data/
│       └── fingerprints.yaml
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
├── requirements.txt
└── pyproject.toml
```

## Setup

Needs Python 3.11+.

```bash
# recommended
uv pip install -e .

# or just pip
pip install -r requirements.txt
```

If you want SYN scanning (`-sS`), `scapy` needs raw socket access:
- Linux/macOS: run with `sudo`
- Windows: install Npcap, then run from an elevated shell

Everything else runs fine unprivileged.

## Using it

```bash
python -m scanner <targets> [options]
```

**Targets** — hostname, single IP, CIDR range, or a file of targets:
```bash
python -m scanner 192.168.1.5
python -m scanner scanme.nmap.org
python -m scanner 10.0.0.0/24
python -m scanner -iL targets.txt
```

**Ports** — explicit list, range, or the N most common:
```bash
python -m scanner 192.168.1.1 -p 22,80,443
python -m scanner 192.168.1.1 -p 1-1024
python -m scanner 192.168.1.1 --top-ports 50
```

**Scan type:**
```bash
python -m scanner 192.168.1.1 -sT   # connect scan (default)
python -m scanner 192.168.1.1 -sS   # SYN scan, needs privileges
python -m scanner 192.168.1.1 -sU   # UDP
```

**Service detection:**
```bash
python -m scanner 192.168.1.1 -sV
python -m scanner 192.168.1.1 -sV --tls-info
```

**Timing** — T0 (slow/careful) through T5 (fast, CTF-style), default T3:
```bash
python -m scanner 192.168.1.1 -T4
```

**Output** — can generate several formats from one run:
```bash
python -m scanner 192.168.1.1 -p 1-1000 -sV -oN report.txt -oJ report.json -oC report.csv -oH report.html
```

## Being polite on the wire

If you're scanning something that can't take a beating (or you just don't want to trip an IDS), cap the rate:
```bash
python -m scanner 192.168.1.1 --rate-limit 50   # max 50 connections/sec
```

## Tests

All tests run against mocked sockets — no live traffic, safe to run anywhere.
```bash
uv pip install -e .[dev]
uv run pytest -v -W error
```
