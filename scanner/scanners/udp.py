import asyncio
import logging
import socket
import time
from typing import Optional
from . import BaseScanner
from ..models import PortResult, PortStatus, ScanProtocol
logger = logging.getLogger(__name__)
DNS_PROBE = b'\x124\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01'
NTP_PROBE = b'\xe3' + b'\x00' * 47
SNMP_PROBE = b'0)\x02\x01\x01\x04\x06public\xa0\x1c\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x000\x0e0\x0c\x06\x08+\x06\x01\x02\x01\x01\x01\x00\x05\x00'
GENERIC_UDP_PAYLOAD = b'\x00' * 4

def get_udp_probe(port: int) -> bytes:
    if port == 53:
        return DNS_PROBE
    elif port == 123:
        return NTP_PROBE
    elif port == 161:
        return SNMP_PROBE
    return GENERIC_UDP_PAYLOAD

class UDPScanner(BaseScanner):

    def __init__(self, retries: int=2):
        self.retries = retries

    async def scan_port(self, host: str, port: int, timeout: float) -> PortResult:
        payload = get_udp_probe(port)
        attempt = 0
        rtt: Optional[float] = None
        status = PortStatus.OPEN_FILTERED
        reason = 'no response (timeout)'
        while attempt <= self.retries:
            attempt += 1
            start_time = time.perf_counter()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                sock.connect((host, port))
                await asyncio.get_running_loop().sock_sendall(sock, payload)
                recv_coro = asyncio.get_running_loop().sock_recv(sock, 512)
                response = await asyncio.wait_for(recv_coro, timeout=timeout)
                rtt = time.perf_counter() - start_time
                status = PortStatus.OPEN
                reason = 'received response'
                banner = response.hex()
                try:
                    decoded = response.decode('utf-8', errors='ignore').strip()
                    if any((c.isprintable() for c in decoded)):
                        banner = decoded
                except Exception:
                    pass
                sock.close()
                return PortResult(port=port, protocol=ScanProtocol.UDP, status=status, rtt=rtt, banner=banner if status == PortStatus.OPEN else None, reason=reason)
            except asyncio.TimeoutError:
                rtt = time.perf_counter() - start_time
                status = PortStatus.OPEN_FILTERED
                reason = f'no response (timeout after {attempt} attempts)'
                sock.close()
                continue
            except (ConnectionRefusedError, ConnectionResetError) as e:
                rtt = time.perf_counter() - start_time
                status = PortStatus.CLOSED
                reason = 'closed (ICMP port unreachable)'
                sock.close()
                break
            except OSError as e:
                rtt = time.perf_counter() - start_time
                if getattr(e, 'winerror', None) == 10054 or e.errno == 10054:
                    status = PortStatus.CLOSED
                    reason = 'closed (ICMP port unreachable)'
                else:
                    status = PortStatus.FILTERED
                    reason = str(e)
                sock.close()
                break
            except Exception as e:
                rtt = time.perf_counter() - start_time
                status = PortStatus.FILTERED
                reason = f'error: {str(e)}'
                sock.close()
                break
        return PortResult(port=port, protocol=ScanProtocol.UDP, status=status, rtt=rtt, reason=reason)
