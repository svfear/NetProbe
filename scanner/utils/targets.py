import ipaddress
import os
import re
from typing import List, Set

def parse_targets(target_specs: List[str]) -> List[str]:
    targets: Set[str] = set()
    for spec in target_specs:
        spec = spec.strip()
        if not spec:
            continue
        if os.path.isfile(spec):
            targets.update(parse_target_file(spec))
            continue
        if '/' in spec:
            try:
                network = ipaddress.ip_network(spec, strict=False)
                for ip in network:
                    targets.add(str(ip))
            except ValueError as e:
                raise ValueError(f'Invalid CIDR specification: {spec}. Details: {e}')
        else:
            if not is_valid_target_spec(spec):
                raise ValueError(f'Invalid target format: {spec}')
            targets.add(spec)
    return sorted(list(targets))

def parse_target_file(filepath: str) -> List[str]:
    targets: Set[str] = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    parsed = parse_targets([line])
                    targets.update(parsed)
                except ValueError:
                    continue
    except Exception as e:
        raise OSError(f'Failed to read target file {filepath}: {e}')
    return list(targets)

def is_valid_target_spec(spec: str) -> bool:
    try:
        ipaddress.ip_address(spec)
        return True
    except ValueError:
        pass
    hostname_regex = '^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?$'
    if re.match(hostname_regex, spec):
        return True
    return False
