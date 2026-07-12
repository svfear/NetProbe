import asyncio
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from .models import HostResult, PortResult, PortStatus, ScanProtocol, ScanReport, ScanTechnique
from .scanners.tcp import TCPConnectScanner, TCPSYNScanner
from .scanners.udp import UDPScanner
from .services.detector import ServiceDetector
from .timing import AdaptiveTiming, TIMING_PROFILES
try:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
logger = logging.getLogger(__name__)

class TokenBucketRateLimiter:

    def __init__(self, rate: float):
        self.rate = rate
        self.capacity = rate
        self.tokens = rate
        self.last_update = time.perf_counter()
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self.lock:
            now = time.perf_counter()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens < 1.0:
                sleep_time = (1.0 - self.tokens) / self.rate
                await asyncio.sleep(sleep_time)
                now = time.perf_counter()
                elapsed = now - self.last_update
                self.last_update = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.tokens -= 1.0

class ScanOrchestrator:

    def __init__(self, targets: List[str], ports: List[int], technique: ScanTechnique=ScanTechnique.TCP_CONNECT, timing_level: int=3, rate_limit: Optional[float]=None, retries: int=1, show_progress: bool=True, service_detection: bool=False, tls_inspection: bool=False):
        self.targets = targets
        self.ports = ports
        self.technique = technique
        self.timing_profile = TIMING_PROFILES[timing_level]
        self.rate_limit = rate_limit
        self.retries = retries
        self.show_progress = show_progress and HAS_RICH
        self.service_detection = service_detection
        self.tls_inspection = tls_inspection
        self.limiter = TokenBucketRateLimiter(rate_limit) if rate_limit else None
        self.semaphore = asyncio.Semaphore(self.timing_profile.max_parallel)
        if technique == ScanTechnique.TCP_CONNECT:
            self.scanner = TCPConnectScanner(retries=retries)
        elif technique == ScanTechnique.TCP_SYN:
            self.scanner = TCPSYNScanner(retries=retries)
        elif technique == ScanTechnique.UDP:
            self.scanner = UDPScanner(retries=retries)
        else:
            raise ValueError(f'Unknown scan technique: {technique}')
        self._detector: Optional[ServiceDetector] = None

    def _get_detector(self) -> ServiceDetector:
        if self._detector is None:
            self._detector = ServiceDetector(tls_enabled=self.tls_inspection)
        return self._detector

    async def _resolve_target(self, target: str) -> Optional[str]:
        try:
            loop = asyncio.get_running_loop()
            addrinfo = await loop.getaddrinfo(target, None, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
            for family, type, proto, canonname, sockaddr in addrinfo:
                return sockaddr[0]
        except Exception as e:
            logger.debug(f'Failed to resolve target hostname {target}: {e}')
        return None

    async def scan(self, command_line: str='') -> ScanReport:
        report = ScanReport(targets=self.targets, ports=self.ports, technique=self.technique, command_line=command_line)
        logger.info(f'Starting {self.technique.value} scan against {len(self.targets)} target(s)...')
        resolved_targets: Dict[str, str] = {}
        for target in self.targets:
            ip = await self._resolve_target(target)
            if ip:
                resolved_targets[target] = ip
                report.hosts[ip] = HostResult(ip=ip, hostname=target if target != ip else None)
            else:
                logger.error(f'Could not resolve target: {target}. Skipping.')
        if not resolved_targets:
            report.end_time = datetime.now(timezone.utc)
            return report
        timing_trackers = {ip: AdaptiveTiming(self.timing_profile) for ip in resolved_targets.values()}
        tasks = []
        for target, ip in resolved_targets.items():
            for port in self.ports:
                tasks.append((ip, port))
        total_tasks = len(tasks)

        async def scan_task(ip: str, port: int, progress_task_id: Optional[Any]=None, progress_bar: Optional[Any]=None) -> None:
            tracker = timing_trackers[ip]
            if self.limiter:
                await self.limiter.wait()
            if self.timing_profile.host_delay > 0:
                await asyncio.sleep(self.timing_profile.host_delay)
            async with self.semaphore:
                timeout = tracker.get_timeout()
                logger.debug(f'Scanning {ip}:{port} with timeout {timeout:.2f}s')
                result = await self.scanner.scan_port(ip, port, timeout)
                if result.rtt is not None and result.status == PortStatus.OPEN:
                    new_timeout = tracker.update_rtt(result.rtt)
                    logger.debug(f'RTT for {ip}:{port} was {result.rtt:.4f}s. New timeout: {new_timeout:.2f}s')
                report.hosts[ip].ports.append(result)
            if progress_bar and progress_task_id is not None:
                progress_bar.update(progress_task_id, advance=1)
        if self.show_progress:
            with Progress(SpinnerColumn(), TextColumn('[progress.description]{task.description}'), BarColumn(bar_width=40), TaskProgressColumn(), TimeRemainingColumn()) as progress:
                p_task = progress.add_task('[cyan]Scanning ports...', total=total_tasks)
                await asyncio.gather(*(scan_task(ip, port, p_task, progress) for ip, port in tasks))
        else:
            await asyncio.gather(*(scan_task(ip, port) for ip, port in tasks))
        if self.service_detection:
            detector = self._get_detector()
            open_results: List[tuple] = []
            for ip, host in report.hosts.items():
                for port_result in host.ports:
                    if port_result.status == PortStatus.OPEN:
                        open_results.append((ip, port_result))
            if open_results:
                logger.info(f'Running service detection on {len(open_results)} open port(s)...')
                if self.show_progress:
                    with Progress(SpinnerColumn(), TextColumn('[progress.description]{task.description}'), BarColumn(bar_width=40), TaskProgressColumn(), TimeRemainingColumn()) as progress:
                        svc_task = progress.add_task('[green]Detecting services...', total=len(open_results))
                        for ip, port_result in open_results:
                            timeout = timing_trackers.get(ip, AdaptiveTiming(self.timing_profile)).get_timeout()
                            await detector.detect(ip, port_result, timeout=timeout)
                            progress.update(svc_task, advance=1)
                else:
                    for ip, port_result in open_results:
                        timeout = timing_trackers.get(ip, AdaptiveTiming(self.timing_profile)).get_timeout()
                        await detector.detect(ip, port_result, timeout=timeout)
        now = datetime.now(timezone.utc)
        report.end_time = now
        for host in report.hosts.values():
            host.end_time = now
        logger.info(f'Scan completed in {report.duration:.2f} seconds.')
        return report
