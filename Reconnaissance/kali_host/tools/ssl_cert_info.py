"""
SSL Certificate Info - Inspect certificate chain and basic TLS details.
Pure Python: uses the built-in ssl module plus certifi for trusted CA bundle.
"""
from typing import Dict, Any, Callable, List, Optional
import socket
import ssl
import datetime


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Inspect a TLS certificate and cipher suite.

    Params:
        host: Hostname of the TLS service
        port: Port (default 443)
    """
    host = params.get("host", "").strip()
    port = params.get("port", 443)

    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 443

    if not host:
        print("[ERROR] No host specified")
        return {"error": "No host specified"}

    print(f"[*] SSL certificate inspection for: {host}:{port}")
    print("=" * 60)

    ctx = _build_ssl_context()

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

        if is_cancelled and is_cancelled():
            return {"error": "Cancelled"}

        info = _parse_cert(cert)
        info["tls_version"] = tls_version
        info["cipher"] = {
            "name": cipher[0] if cipher else None,
            "protocol": cipher[1] if cipher else None,
            "bits": cipher[2] if cipher else None,
        }
        info["host"] = host
        info["port"] = port

        _print_info(info)

        if on_progress:
            on_progress(1, 1)

        return info

    except ssl.CertificateError as e:
        print(f"[ERROR] Certificate validation error: {e}")
        return {"error": f"Certificate error: {e}"}
    except ssl.SSLError as e:
        print(f"[ERROR] SSL error: {e}")
        return {"error": str(e)}
    except socket.timeout:
        print(f"[ERROR] Connection timed out to {host}:{port}")
        return {"error": "Connection timed out"}
    except ConnectionRefusedError:
        print(f"[ERROR] Connection refused by {host}:{port}")
        return {"error": "Connection refused"}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}


def _build_ssl_context() -> ssl.SSLContext:
    """Create an SSL context that uses certifi's trusted CA bundle if available."""
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _parse_cert(cert: Dict[str, Any]) -> Dict[str, Any]:
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    not_before = _parse_asn1_time(cert.get("notBefore"))
    not_after = _parse_asn1_time(cert.get("notAfter"))
    san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

    days_left: Optional[int] = None
    expired = False
    if not_after:
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        days_left = (not_after - now).days
        expired = days_left < 0

    serial = cert.get("serialNumber")

    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_left": days_left,
        "expired": expired,
        "san": san,
        "serial_number": serial,
    }


def _parse_asn1_time(value: Optional[str]) -> Optional[datetime.datetime]:
    if not value:
        return None
    try:
        return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None


def _print_info(info: Dict[str, Any]) -> None:
    print("\n--- Subject ---")
    for k, v in info.get("subject", {}).items():
        print(f"  {k}: {v}")

    print("\n--- Issuer ---")
    for k, v in info.get("issuer", {}).items():
        print(f"  {k}: {v}")

    print("\n--- Validity ---")
    print(f"  Not Before : {info.get('not_before')}")
    print(f"  Not After  : {info.get('not_after')}")
    days = info.get("days_left")
    if days is not None:
        if info.get("expired"):
            print(f"  [!] EXPIRED ({abs(days)} days ago)")
        elif days <= 30:
            print(f"  [!] Expiring soon: {days} day(s) remaining")
        else:
            print(f"  Days left  : {days}")

    san = info.get("san", [])
    if san:
        print("\n--- Subject Alternative Names (DNS) ---")
        for name in san:
            print(f"  - {name}")

    print("\n--- TLS ---")
    cipher = info.get("cipher", {})
    print(f"  Version : {info.get('tls_version')}")
    if cipher.get("name"):
        print(f"  Cipher  : {cipher.get('name')} ({cipher.get('bits')} bits, {cipher.get('protocol')})")

    print("=" * 60)
    print("[*] SSL certificate inspection complete")
