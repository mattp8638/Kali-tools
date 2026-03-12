from typing import Any, Callable, Dict, List

from scanning_host.core.common import normalize_host, safe_int, socket_connect


def _grab(host: str, port: int, timeout: float) -> Dict[str, Any]:
    try:
        s = socket_connect(host, port, timeout)
        try:
            s.sendall(b"\r\n")
        except Exception:
            pass
        data = b""
        try:
            data = s.recv(4096)
        except Exception:
            pass
        s.close()
        return {"port": port, "open": True, "banner": data.decode(errors="ignore").strip()}
    except Exception as e:
        return {"port": port, "open": False, "error": str(e)}


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    host = normalize_host(params.get("target", ""))
    timeout = float(params.get("timeout", 2))
    ports_raw = params.get("ports", "21,22,25,80,110,143,443,445,3389")

    if not host:
        return {"error": "target is required"}

    print("[*] Banner grab starting")
    print(f"[*] Target: {host}")

    ports: List[int] = []
    for part in str(ports_raw).split(","):
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

    rows = []
    for i, port in enumerate(ports, start=1):
        if is_cancelled and is_cancelled():
            break
        if on_progress:
            on_progress(i, len(ports))
        row = _grab(host, port, timeout)
        rows.append(row)
        if row.get("open"):
            banner = row.get("banner", "")
            print(f"[+] Port {port} open" + (f" -> {banner}" if banner else ""))

    print(f"[*] Banner grab complete: {len([r for r in rows if r.get('open')])} open port(s)")
    return {
        "target": host,
        "total_ports": len(ports),
        "open_ports": [r for r in rows if r.get("open")],
        "results": rows,
    }
