import asyncio
import logging
import socket
import time
from typing import Optional
from . import BaseScanner
from ..models import PortResult, PortStatus, ScanProtocol
logger = logging.getLogger(__name__)
try:
    from scapy.all import IP, TCP, sr1, send, RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def check_raw_socket_privilege() -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.close()
        return True
    except PermissionError:
        return False
    except OSError as e:
        logger.debug(f'Raw socket check failed with OS error: {e}')
        return False

class TCPConnectScanner(BaseScanner):

    def __init__(self, retries: int=1):
        self.retries = retries

    async def scan_port(self, host: str, port: int, timeout: float) -> PortResult:
        attempt = 0
        rtt: Optional[float] = None
        status = PortStatus.FILTERED
        reason = 'timeout'
        while attempt <= self.retries:
            attempt += 1
            start_time = time.perf_counter()
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                rtt = time.perf_counter() - start_time
                status = PortStatus.OPEN
                reason = 'connection established'
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                break
            except asyncio.TimeoutError:
                rtt = time.perf_counter() - start_time
                status = PortStatus.FILTERED
                reason = f'timeout (attempt {attempt}/{self.retries + 1})'
                continue
            except ConnectionRefusedError:
                rtt = time.perf_counter() - start_time
                status = PortStatus.CLOSED
                reason = 'connection refused'
                break
            except OSError as e:
                rtt = time.perf_counter() - start_time
                status = PortStatus.FILTERED
                reason = str(e)
                break
            except Exception as e:
                rtt = time.perf_counter() - start_time
                status = PortStatus.FILTERED
                reason = f'error: {str(e)}'
                break
        return PortResult(port=port, protocol=ScanProtocol.TCP, status=status, rtt=rtt, reason=reason)

class TCPSYNScanner(BaseScanner):

    def __init__(self, retries: int=1):
        self.retries = retries
        self.has_scapy = SCAPY_AVAILABLE
        self.has_privilege = check_raw_socket_privilege()
        self.fallback_scanner = TCPConnectScanner(retries=retries)
        if not self.has_scapy:
            logger.warning('Scapy is not installed. SYN scan will fallback to TCP Connect scan.')
        elif not self.has_privilege:
            logger.warning('Elevated privileges/raw socket permissions not available. SYN scan will fallback to TCP Connect scan.')

    async def scan_port(self, host: str, port: int, timeout: float) -> PortResult:
        if not self.has_scapy or not self.has_privilege:
            return await self.fallback_scanner.scan_port(host, port, timeout)
        attempt = 0
        rtt: Optional[float] = None
        status = PortStatus.FILTERED
        reason = 'no response'
        while attempt <= self.retries:
            attempt += 1
            start_time = time.perf_counter()
            try:
                response = await asyncio.to_thread(self._scapy_syn_probe, host, port, timeout)
                rtt = time.perf_counter() - start_time
                if response is None:
                    status = PortStatus.FILTERED
                    reason = f'no response (timeout after {attempt} attempts)'
                    continue
                if response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)
                    flags = tcp_layer.flags
                    if flags & 18 == 18:
                        status = PortStatus.OPEN
                        reason = 'syn-ack received'
                        await asyncio.to_thread(self._scapy_send_rst, host, port, tcp_layer.sport)
                        break
                    elif flags & 4 or flags & 20:
                        status = PortStatus.CLOSED
                        reason = 'rst received'
                        break
                elif response.haslayer('ICMP'):
                    icmp_layer = response.getlayer('ICMP')
                    if icmp_layer.type == 3:
                        status = PortStatus.FILTERED
                        reason = f'icmp destination unreachable (type {icmp_layer.type}, code {icmp_layer.code})'
                        break
            except Exception as e:
                rtt = time.perf_counter() - start_time
                status = PortStatus.FILTERED
                reason = f'scapy error: {str(e)}'
                break
        return PortResult(port=port, protocol=ScanProtocol.TCP, status=status, rtt=rtt, reason=reason)

    def _scapy_syn_probe(self, host: str, port: int, timeout: float):
        sport = RandShort()
        packet = IP(dst=host) / TCP(sport=sport, dport=port, flags='S')
        return sr1(packet, timeout=timeout, verbose=0)

    def _scapy_send_rst(self, host: str, port: int, sport: int) -> None:
        rst_packet = IP(dst=host) / TCP(sport=sport, dport=port, flags='R')
        send(rst_packet, verbose=0)
