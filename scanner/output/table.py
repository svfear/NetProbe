import sys
from typing import IO, Optional
from ..models import HostResult, PortStatus, ScanReport
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

class TableFormatter:

    def format(self, report: ScanReport, file: IO=sys.stdout) -> None:
        if HAS_RICH:
            self._rich_format(report, file)
        else:
            self._plain_format(report, file)

    def _rich_format(self, report: ScanReport, file: IO) -> None:
        console = Console(file=file)
        header_text = Text()
        header_text.append('NetProbe Scan Report\n', style='bold cyan')
        header_text.append(f'Technique: {report.technique.value}\n')
        header_text.append(f'Start: {report.start_time.isoformat()}\n')
        if report.end_time:
            header_text.append(f'End:   {report.end_time.isoformat()}\n')
        header_text.append(f'Duration: {report.duration:.2f}s\n')
        header_text.append(f'Hosts: {len(report.hosts)}')
        console.print(Panel(header_text, title='Scan Summary', border_style='cyan'))
        for ip, host in report.hosts.items():
            hostname_str = f' ({host.hostname})' if host.hostname else ''
            console.print(f'\n[bold white]Host: {ip}{hostname_str}[/bold white]')
            if host.os_guess:
                console.print(f'  OS Guess: {host.os_guess} ({host.os_confidence:.0f}%)', style='dim')
            open_ports = [p for p in host.ports if p.status == PortStatus.OPEN]
            if not open_ports:
                console.print('  No open ports found.', style='dim yellow')
                continue
            table = Table(show_header=True, header_style='bold magenta', box=None, pad_edge=False)
            table.add_column('PORT', style='cyan', width=8)
            table.add_column('STATE', style='green', width=8)
            table.add_column('SERVICE', style='yellow', width=16)
            table.add_column('PRODUCT', width=22)
            table.add_column('VERSION', width=12)
            table.add_column('CONF', justify='right', width=6)
            table.add_column('REASON', style='dim')
            for p in sorted(open_ports, key=lambda x: x.port):
                conf = f'{p.confidence:.0f}%' if p.confidence > 0 else ''
                table.add_row(str(p.port), p.status.value, p.service_name, p.product or '', p.version or '', conf, p.reason)
                if p.tls_info:
                    tls_detail = f'  TLS: {p.tls_info.tls_version} | {p.tls_info.cipher_suite}'
                    if p.tls_info.subject:
                        tls_detail += f' | {p.tls_info.subject}'
                    table.add_row('', '', '', tls_detail, '', '', '', style='dim cyan')
            console.print(table)

    def _plain_format(self, report: ScanReport, file: IO) -> None:
        print(f'\nNetProbe Scan Report', file=file)
        print(f'Technique: {report.technique.value}', file=file)
        print(f'Duration: {report.duration:.2f}s', file=file)
        print(f'Hosts: {len(report.hosts)}\n', file=file)
        for ip, host in report.hosts.items():
            hostname_str = f' ({host.hostname})' if host.hostname else ''
            print(f'Host: {ip}{hostname_str}', file=file)
            open_ports = [p for p in host.ports if p.status == PortStatus.OPEN]
            if not open_ports:
                print('  No open ports found.\n', file=file)
                continue
            print(f"  {'PORT':<8s} {'STATE':<8s} {'SERVICE':<16s} {'PRODUCT':<20s} {'VERSION':<10s}", file=file)
            for p in sorted(open_ports, key=lambda x: x.port):
                print(f"  {p.port:<8d} {p.status.value:<8s} {p.service_name:<16s} {p.product or '':<20s} {p.version or '':<10s}", file=file)
            print(file=file)
