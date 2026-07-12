import asyncio
import logging
import ssl
from typing import Optional
from ..models import TLSInfo
logger = logging.getLogger(__name__)

async def inspect_tls(host: str, port: int, timeout: float=5.0) -> Optional[TLSInfo]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        conn = asyncio.open_connection(host, port, ssl=ctx)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        transport = writer.transport
        ssl_object = transport.get_extra_info('ssl_object')
        tls_info = TLSInfo(subject='', issuer='')
        if ssl_object:
            cert = ssl_object.getpeercert(binary_form=False)
            if cert:
                tls_info.subject = _format_dn(cert.get('subject', ()))
                tls_info.issuer = _format_dn(cert.get('issuer', ()))
                tls_info.sans = _extract_sans(cert)
            else:
                der_cert = ssl_object.getpeercert(binary_form=True)
                if der_cert:
                    tls_info.subject = '(certificate present, details unavailable without verification)'
            tls_info.tls_version = ssl_object.version() or ''
            cipher_info = ssl_object.cipher()
            if cipher_info:
                tls_info.cipher_suite = cipher_info[0]
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return tls_info
    except asyncio.TimeoutError:
        logger.debug(f'TLS inspection timed out for {host}:{port}')
        return None
    except ssl.SSLError as e:
        logger.debug(f'TLS error for {host}:{port}: {e}')
        return None
    except ConnectionRefusedError:
        logger.debug(f'Connection refused for TLS inspection at {host}:{port}')
        return None
    except OSError as e:
        logger.debug(f'OS error during TLS inspection for {host}:{port}: {e}')
        return None
    except Exception as e:
        logger.debug(f'Unexpected error during TLS inspection for {host}:{port}: {e}')
        return None

def _format_dn(dn_tuple: tuple) -> str:
    parts = []
    dn_map = {'commonName': 'CN', 'organizationName': 'O', 'organizationalUnitName': 'OU', 'countryName': 'C', 'stateOrProvinceName': 'ST', 'localityName': 'L'}
    for rdn in dn_tuple:
        for attr_type, attr_value in rdn:
            short = dn_map.get(attr_type, attr_type)
            parts.append(f'{short}={attr_value}')
    return ', '.join(parts)

def _extract_sans(cert: dict) -> list:
    sans = []
    for san_type, san_value in cert.get('subjectAltName', ()):
        sans.append(f'{san_type}:{san_value}')
    return sans
