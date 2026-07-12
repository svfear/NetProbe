import json
from datetime import datetime
from typing import Any, IO
from ..models import ScanReport

class DateTimeEncoder(json.JSONEncoder):

    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class JSONFormatter:

    def format(self, report: ScanReport, file: IO) -> None:
        report_dict = self._to_dict(report)
        json.dump(report_dict, file, cls=DateTimeEncoder, indent=2)

    def _to_dict(self, report: ScanReport) -> dict:
        hosts_dict = {}
        for ip, host in report.hosts.items():
            ports_list = []
            for p in host.ports:
                port_dict = {'port': p.port, 'protocol': p.protocol.value, 'status': p.status.value, 'service_name': p.service_name, 'product': p.product, 'version': p.version, 'confidence': p.confidence, 'banner': p.banner, 'rtt': p.rtt, 'reason': p.reason, 'tls_info': None}
                if p.tls_info:
                    port_dict['tls_info'] = {'subject': p.tls_info.subject, 'issuer': p.tls_info.issuer, 'sans': p.tls_info.sans, 'tls_version': p.tls_info.tls_version, 'cipher_suite': p.tls_info.cipher_suite}
                ports_list.append(port_dict)
            hosts_dict[ip] = {'ip': host.ip, 'hostname': host.hostname, 'os_guess': host.os_guess, 'os_confidence': host.os_confidence, 'start_time': host.start_time, 'end_time': host.end_time, 'duration': host.duration, 'ports': ports_list}
        return {'scanner': 'NetProbe', 'scanner_version': report.scanner_version, 'command_line': report.command_line, 'technique': report.technique.value, 'start_time': report.start_time, 'end_time': report.end_time, 'duration': report.duration, 'targets': report.targets, 'ports_scanned': report.ports, 'hosts': hosts_dict}
