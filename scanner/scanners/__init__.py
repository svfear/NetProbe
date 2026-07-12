from abc import ABC, abstractmethod
from ..models import PortResult

class BaseScanner(ABC):

    @abstractmethod
    async def scan_port(self, host: str, port: int, timeout: float) -> PortResult:
        pass
