import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import yaml
logger = logging.getLogger(__name__)
_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
DEFAULT_FINGERPRINTS_PATH = os.path.join(_DATA_DIR, 'fingerprints.yaml')

@dataclass
class MatchRule:
    service: str
    pattern: str
    product: Optional[str] = None
    version: Optional[str] = None
    confidence: float = 50.0
    _compiled: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def compile(self) -> None:
        if self._compiled is None:
            try:
                self._compiled = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
            except re.error as e:
                logger.warning(f'Invalid regex in fingerprint DB: {self.pattern!r} — {e}')
                self._compiled = None

@dataclass
class MatchResult:
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    confidence: float = 0.0

@dataclass
class Probe:
    name: str
    protocol: str
    payload: str
    ports: List[int] = field(default_factory=list)
    rarity: int = 5
    matches: List[MatchRule] = field(default_factory=list)

    def get_payload_bytes(self, host: str='') -> bytes:
        payload = self.payload.replace('{host}', host)
        payload = payload.replace('\\r', '\r').replace('\\n', '\n').replace('\\t', '\t')
        try:
            return payload.encode('utf-8')
        except UnicodeEncodeError:
            return payload.encode('latin-1')

@dataclass
class PortHint:
    service: str
    confidence: float = 25.0

class FingerprintDB:

    def __init__(self, path: Optional[str]=None):
        self.path = path or DEFAULT_FINGERPRINTS_PATH
        self.probes: List[Probe] = []
        self.port_hints: Dict[int, PortHint] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f'Fingerprint database not found at {self.path}')
            return
        except yaml.YAMLError as e:
            logger.error(f'Failed to parse fingerprint database: {e}')
            return
        for probe_data in data.get('probes', []):
            match_rules = []
            for m in probe_data.get('matches', []):
                rule = MatchRule(service=m['service'], pattern=m['pattern'], product=m.get('product'), version=m.get('version'), confidence=m.get('confidence', 50.0))
                rule.compile()
                match_rules.append(rule)
            probe = Probe(name=probe_data['name'], protocol=probe_data.get('protocol', 'tcp'), payload=probe_data.get('payload', ''), ports=probe_data.get('ports', []), rarity=probe_data.get('rarity', 5), matches=match_rules)
            self.probes.append(probe)
        self.probes.sort(key=lambda p: p.rarity)
        for port_str, hint_data in data.get('port_hints', {}).items():
            port = int(port_str)
            self.port_hints[port] = PortHint(service=hint_data['service'], confidence=hint_data.get('confidence', 25.0))
        logger.debug(f'Loaded {len(self.probes)} probes and {len(self.port_hints)} port hints')

    def get_null_probe(self) -> Optional[Probe]:
        for probe in self.probes:
            if probe.name == 'NULL':
                return probe
        return None

    def get_probes_for_port(self, port: int) -> List[Probe]:
        result = []
        for probe in self.probes:
            if probe.name == 'NULL':
                continue
            if not probe.ports or port in probe.ports:
                result.append(probe)
        return result

    def get_port_hint(self, port: int) -> Optional[MatchResult]:
        hint = self.port_hints.get(port)
        if hint:
            return MatchResult(service=hint.service, confidence=hint.confidence)
        return None

    @staticmethod
    def match_response(response: str, rules: List[MatchRule]) -> Optional[MatchResult]:
        best: Optional[MatchResult] = None
        for rule in rules:
            if rule._compiled is None:
                continue
            m = rule._compiled.search(response)
            if m:
                product = _substitute_groups(rule.product, m) if rule.product else None
                version = _substitute_groups(rule.version, m) if rule.version else None
                result = MatchResult(service=rule.service, product=product, version=version, confidence=rule.confidence)
                if best is None or result.confidence > best.confidence:
                    best = result
        return best

def _substitute_groups(template: Optional[str], match: re.Match) -> Optional[str]:
    if template is None:
        return None
    result = template
    for i in range(1, 10):
        placeholder = f'${i}'
        if placeholder in result:
            group_val = match.group(i) if i <= len(match.groups()) else ''
            result = result.replace(placeholder, group_val or '')
    return result
