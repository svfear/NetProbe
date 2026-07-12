import asyncio
import logging
from typing import Optional
from ..models import PortResult, PortStatus
from .fingerprints import FingerprintDB, MatchResult, Probe
from .tls_inspector import inspect_tls
logger = logging.getLogger(__name__)
TLS_PORTS = {443, 465, 636, 853, 993, 995, 3389, 5061, 8443}

class ServiceDetector:

    def __init__(self, db: Optional[FingerprintDB]=None, tls_enabled: bool=True):
        self.db = db or FingerprintDB()
        self.tls_enabled = tls_enabled

    async def detect(self, host: str, port_result: PortResult, timeout: float=3.0) -> PortResult:
        if port_result.status != PortStatus.OPEN:
            return port_result
        port = port_result.port
        logger.debug(f'Stage 1 (NULL probe) for {host}:{port}')
        match = await self._stage_null_probe(host, port, timeout)
        if match and match.confidence >= 80:
            self._apply_match(port_result, match)
            return port_result
        best_match = match
        logger.debug(f'Stage 2 (protocol probes) for {host}:{port}')
        probes = self.db.get_probes_for_port(port)
        for probe in probes:
            probe_match = await self._stage_protocol_probe(host, port, probe, timeout)
            if probe_match:
                if best_match is None or probe_match.confidence > best_match.confidence:
                    best_match = probe_match
                if best_match.confidence >= 80:
                    break
        if best_match and best_match.confidence >= 60:
            self._apply_match(port_result, best_match)
            return port_result
        if self.tls_enabled and (port in TLS_PORTS or port_result.service_name == 'unknown'):
            logger.debug(f'Stage 3 (TLS inspection) for {host}:{port}')
            tls_info = await inspect_tls(host, port, timeout)
            if tls_info and (tls_info.subject or tls_info.tls_version):
                port_result.tls_info = tls_info
                if not best_match or best_match.confidence < 50:
                    best_match = MatchResult(service='ssl/https' if port in {443, 8443} else 'ssl/tls', product=f'TLS ({tls_info.tls_version})' if tls_info.tls_version else None, confidence=55.0)
        if best_match and best_match.confidence > 0:
            self._apply_match(port_result, best_match)
            return port_result
        logger.debug(f'Stage 4 (port heuristic) for {host}:{port}')
        hint = self.db.get_port_hint(port)
        if hint:
            self._apply_match(port_result, hint)
        return port_result

    async def _stage_null_probe(self, host: str, port: int, timeout: float) -> Optional[MatchResult]:
        null_probe = self.db.get_null_probe()
        if not null_probe:
            return None
        banner = await self._send_probe(host, port, b'', timeout)
        if not banner:
            return None
        return self.db.match_response(banner, null_probe.matches)

    async def _stage_protocol_probe(self, host: str, port: int, probe: Probe, timeout: float) -> Optional[MatchResult]:
        payload = probe.get_payload_bytes(host=host)
        response = await self._send_probe(host, port, payload, timeout)
        if not response:
            return None
        return self.db.match_response(response, probe.matches)

    async def _send_probe(self, host: str, port: int, payload: bytes, timeout: float) -> Optional[str]:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            if payload:
                writer.write(payload)
                await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except asyncio.TimeoutError:
                data = b''
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if data:
                try:
                    return data.decode('utf-8', errors='replace')
                except Exception:
                    return data.decode('latin-1', errors='replace')
            return None
        except asyncio.TimeoutError:
            return None
        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            logger.debug(f'Probe connection error to {host}:{port}: {e}')
            return None
        except Exception as e:
            logger.debug(f'Unexpected probe error to {host}:{port}: {e}')
            return None

    @staticmethod
    def _apply_match(port_result: PortResult, match: MatchResult) -> None:
        port_result.service_name = match.service
        if match.product:
            port_result.product = match.product
        if match.version:
            port_result.version = match.version
        port_result.confidence = match.confidence
