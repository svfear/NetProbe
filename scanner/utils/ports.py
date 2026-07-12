import re
from typing import List, Set
TOP_100_PORTS = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9100, 9999, 32768, 32778, 49152, 49153, 49154, 49155, 49156, 49157]
TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

def parse_ports(port_spec: str) -> List[int]:
    ports: Set[int] = set()
    parts = [p.strip() for p in port_spec.split(',') if p.strip()]
    for part in parts:
        if '-' in part:
            match = re.match('^(\\d+)-(\\d+)$', part)
            if not match:
                raise ValueError(f'Invalid port range format: {part}')
            start, end = (int(match.group(1)), int(match.group(2)))
            if start > end:
                raise ValueError(f'Start port cannot be greater than end port in range: {part}')
            for p in range(start, end + 1):
                if not 1 <= p <= 65535:
                    raise ValueError(f'Port {p} out of range (1-65535)')
                ports.add(p)
        else:
            if not part.isdigit():
                raise ValueError(f'Invalid port specification: {part}')
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f'Port {p} out of range (1-65535)')
            ports.add(p)
    return sorted(list(ports))

def get_top_ports(count: int) -> List[int]:
    if count <= 20:
        return TOP_20_PORTS[:count]
    return TOP_100_PORTS[:count]
