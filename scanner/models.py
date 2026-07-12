from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any

class PortStatus(str, Enum):
    OPEN = 'open'
    CLOSED = 'closed'
    FILTERED = 'filtered'
    OPEN_FILTERED = 'open|filtered'

class ScanProtocol(str, Enum):
    TCP = 'TCP'
    UDP = 'UDP'

class ScanTechnique(str, Enum):
    TCP_CONNECT = 'TCP Connect'
    TCP_SYN = 'TCP SYN'
    UDP = 'UDP'

@dataclass
class TLSInfo:
    subject: str
    issuer: str
    sans: List[str] = field(default_factory=list)
    tls_version: str = ''
    cipher_suite: str = ''

@dataclass
class PortResult:
    port: int
    protocol: ScanProtocol
    status: PortStatus
    service_name: str = 'unknown'
    product: Optional[str] = None
    version: Optional[str] = None
    confidence: float = 0.0
    banner: Optional[str] = None
    tls_info: Optional[TLSInfo] = None
    rtt: Optional[float] = None
    reason: str = ''

@dataclass
class HostResult:
    ip: str
    hostname: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)
    os_guess: Optional[str] = None
    os_confidence: float = 0.0
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None

    @property
    def duration(self) -> float:
        if not self.end_time:
            return (datetime.now(timezone.utc) - self.start_time).total_seconds()
        return (self.end_time - self.start_time).total_seconds()

@dataclass
class ScanReport:
    targets: List[str]
    ports: List[int]
    technique: ScanTechnique
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    hosts: Dict[str, HostResult] = field(default_factory=dict)
    command_line: str = ''
    scanner_version: str = '1.0.0'

    @property
    def duration(self) -> float:
        if not self.end_time:
            return (datetime.now(timezone.utc) - self.start_time).total_seconds()
        return (self.end_time - self.start_time).total_seconds()
