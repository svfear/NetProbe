import argparse
import sys
from typing import List, Optional
from .core import ScanOrchestrator
from .models import ScanTechnique
from .utils.log import setup_logging
from .utils.ports import parse_ports, get_top_ports
from .utils.targets import parse_targets

def parse_args(args: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='NetProbe — A production-quality authorized network reconnaissance and port scanning tool.', formatter_class=argparse.RawTextHelpFormatter, epilog='Examples:\n  netprobe 192.168.1.10 -p 22,80,443\n  netprobe 10.0.0.0/24 -p 1-1024 -T4\n  netprobe targets.txt --top-ports 50\n')
    disclaimer = 'WARNING: This software is intended solely for use against systems and networks\nthat you own or are explicitly authorized to assess. Unauthorized scanning may\nviolate laws, regulations, organizational policies, or contractual agreements.'
    parser.add_argument('--acknowledge-disclaimer', action='store_true', help='Acknowledge the legal disclaimer and run the scan.')
    target_group = parser.add_argument_group('Target Selection')
    target_group.add_argument('targets', nargs='*', help='Target IP addresses, hostnames, CIDR blocks, or files containing targets.')
    target_group.add_argument('-iL', '--input-file', help='Read targets from the specified file.')
    port_group = parser.add_argument_group('Port Selection')
    port_group.add_argument('-p', '--ports', help="Port specification (e.g. '80', '1-1024', '22,80,443').")
    port_group.add_argument('--top-ports', type=int, help='Scan the specified number of top common ports (default top 100 if no ports specified).')
    technique_group = parser.add_argument_group('Scan Techniques')
    technique_group.add_argument('-sT', action='store_true', dest='scan_tcp_connect', help='Perform a TCP Connect Scan (Default, no elevated privileges needed).')
    technique_group.add_argument('-sS', action='store_true', dest='scan_tcp_syn', help='Perform a TCP SYN Scan (Requires elevated privileges, uses Scapy).')
    technique_group.add_argument('-sU', action='store_true', dest='scan_udp', help='Perform a UDP Scan (Uses protocol-specific probes for high accuracy).')
    timing_group = parser.add_argument_group('Timing & Performance')
    timing_group.add_argument('-T', '--timing', type=int, choices=[0, 1, 2, 3, 4, 5], default=3, help='Timing profile: 0 (paranoid) to 5 (insane) (default: 3).')
    timing_group.add_argument('--timeout', type=float, help='Override default timeout for port probes (seconds).')
    timing_group.add_argument('--rate-limit', type=float, help='Maximum connections/packets per second.')
    timing_group.add_argument('--retries', type=int, default=1, help='Number of port scan retries (default: 1).')
    service_group = parser.add_argument_group('Service & Version Detection')
    service_group.add_argument('-sV', '--service-version', action='store_true', help='Enable service and version detection.')
    service_group.add_argument('--tls-info', action='store_true', help='Enable TLS certificate inspection on open ports.')
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-oN', '--output-text', help='Write scan report in human-readable text table format to file.')
    output_group.add_argument('-oJ', '--output-json', help='Write scan report in JSON format to file.')
    output_group.add_argument('-oC', '--output-csv', help='Write scan report in CSV format to file.')
    output_group.add_argument('-oH', '--output-html', help='Write scan report in HTML format to file.')
    log_group = parser.add_argument_group('Verbosity & Debugging')
    log_group.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity level (use -v, -vv for info/debug).')
    log_group.add_argument('--debug', action='store_true', help='Enable full debugging logs.')
    return parser.parse_args(args)

def main(args_list: Optional[List[str]]=None) -> None:
    if args_list is None:
        args_list = sys.argv[1:]
    args = parse_args(args_list)
    setup_logging(args.verbose, args.debug)
    print('\n========================================================================\n                     NetProbe Authorized Scanner v1.0.0\n========================================================================\nThis software is intended solely for use against systems and networks that\nyou own or are explicitly authorized to assess. Unauthorized scanning may\nviolate laws, regulations, organizational policies, or contractual agreements.\n========================================================================\n', file=sys.stderr)
    target_list = list(args.targets)
    if args.input_file:
        target_list.append(args.input_file)
    if not target_list:
        print('[-] Error: No targets specified. Use target IPs, hostnames, CIDRs or an input file.', file=sys.stderr)
        sys.exit(1)
    try:
        resolved_targets = parse_targets(target_list)
    except Exception as e:
        print(f'[-] Error parsing targets: {e}', file=sys.stderr)
        sys.exit(1)
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except Exception as e:
            print(f'[-] Error parsing ports: {e}', file=sys.stderr)
            sys.exit(1)
    else:
        top_count = args.top_ports if args.top_ports else 100
        ports = get_top_ports(top_count)
    technique = ScanTechnique.TCP_CONNECT
    if args.scan_tcp_syn:
        technique = ScanTechnique.TCP_SYN
    elif args.scan_udp:
        technique = ScanTechnique.UDP
    import asyncio
    orchestrator = ScanOrchestrator(targets=resolved_targets, ports=ports, technique=technique, timing_level=args.timing, rate_limit=args.rate_limit, retries=args.retries, show_progress=True, service_detection=args.service_version, tls_inspection=args.tls_info)
    cmd_line = ' '.join(sys.argv)
    from .output import TableFormatter, JSONFormatter, CSVFormatter, HTMLFormatter
    try:
        report = asyncio.run(orchestrator.scan(command_line=cmd_line))
        table_formatter = TableFormatter()
        table_formatter.format(report, sys.stdout)
        if args.output_text:
            try:
                with open(args.output_text, 'w', encoding='utf-8') as f:
                    table_formatter.format(report, f)
                print(f'[+] Human-readable report written to: {args.output_text}')
            except Exception as e:
                print(f'[-] Failed to write text report to {args.output_text}: {e}', file=sys.stderr)
        if args.output_json:
            try:
                with open(args.output_json, 'w', encoding='utf-8') as f:
                    JSONFormatter().format(report, f)
                print(f'[+] JSON report written to: {args.output_json}')
            except Exception as e:
                print(f'[-] Failed to write JSON report to {args.output_json}: {e}', file=sys.stderr)
        if args.output_csv:
            try:
                with open(args.output_csv, 'w', newline='', encoding='utf-8') as f:
                    CSVFormatter().format(report, f)
                print(f'[+] CSV report written to: {args.output_csv}')
            except Exception as e:
                print(f'[-] Failed to write CSV report to {args.output_csv}: {e}', file=sys.stderr)
        if args.output_html:
            try:
                with open(args.output_html, 'w', encoding='utf-8') as f:
                    HTMLFormatter().format(report, f)
                print(f'[+] HTML report written to: {args.output_html}')
            except Exception as e:
                print(f'[-] Failed to write HTML report to {args.output_html}: {e}', file=sys.stderr)
    except KeyboardInterrupt:
        print('\n[-] Scan cancelled by user.', file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f'\n[-] Critical error during scan: {e}', file=sys.stderr)
        sys.exit(1)
if __name__ == '__main__':
    main()
