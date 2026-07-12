import logging
import sys
from typing import Optional

def setup_logging(verbosity: int, debug: bool=False) -> None:
    if debug or verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    try:
        from rich.logging import RichHandler
        handler = RichHandler(rich_tracebacks=True, markup=True, show_time=True, show_path=False)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
    except ImportError:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)
    root_logger.addHandler(handler)
    root_logger.setLevel(level)
    logging.getLogger('scapy').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)
