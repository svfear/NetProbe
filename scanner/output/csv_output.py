import csv
from typing import IO
from ..models import ScanReport

class CSVFormatter:

    def format(self, report: ScanReport, file: IO) -> None:
        writer = csv.writer(file)
        writer.writerow(['IP', 'Hostname', 'Port', 'Protocol', 'Status', 'Service', 'Product', 'Version', 'Confidence', 'RTT', 'Reason', 'TLS Version', 'Cipher Suite', 'TLS Subject'])
        for ip, host in report.hosts.items():
            hostname = host.hostname or ''
            for p in sorted(host.ports, key=lambda x: x.port):
                tls_version = ''
                tls_cipher = ''
                tls_subject = ''
                if p.tls_info:
                    tls_version = p.tls_info.tls_version
                    tls_cipher = p.tls_info.cipher_suite
                    tls_subject = p.tls_info.subject
                writer.writerow([ip, hostname, p.port, p.protocol.value, p.status.value, p.service_name, p.product or '', p.version or '', f'{p.confidence:.0f}%' if p.confidence > 0 else '', f'{p.rtt:.4f}' if p.rtt is not None else '', p.reason, tls_version, tls_cipher, tls_subject])
