import socket
from typing import Any, Dict, List

from scanning_host.core.common import normalize_host, safe_int


def _parse_ports(spec: str) -> List[int]:
    ports: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            for p in range(safe_int(a, 0), safe_int(b, 0) + 1):
                if 1 <= p <= 65535:
                    ports.append(p)
        else:
            p = safe_int(part, 0)
            if 1 <= p <= 65535:
                ports.append(p)
    return sorted(set(ports))


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    host = normalize_host(params.get("target", ""))
    timeout = float(params.get("timeout", 1.5))
    ports = _parse_ports(str(params.get("ports", "53,67,68,69,123,137,161,500,514,520,1900,5353")))

    if not host:
        return {"error": "target is required"}

    open_or_filtered = []
    closed = []

    for i, port in enumerate(ports, start=1):
        if is_cancelled and is_cancelled():
            break
        if on_progress:
            on_progress(i, len(ports))

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(b"\x00", (host, port))
            data, _ = s.recvfrom(2048)
            open_or_filtered.append({"port": port, "state": "open", "response_len": len(data)})
        except socket.timeout:
            open_or_filtered.append({"port": port, "state": "open|filtered"})
        except Exception as e:
            closed.append({"port": port, "state": "closed", "error": str(e)})
        finally:
            s.close()

    return {
        "target": host,
        "tested": len(ports),
        "open_or_filtered": open_or_filtered,
        "closed": closed,
    }
