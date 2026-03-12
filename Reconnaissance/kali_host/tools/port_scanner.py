"""
Port Scanner - TCP port scanning with service detection.
Pure Python implementation (no nmap dependency).
"""
import socket
import concurrent.futures
from typing import Dict, Any, Callable, List, Tuple


# Common service names
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Top 100 ports (common scan target)
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 179, 199, 389, 427, 443, 444, 445, 465, 513,
    514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156, 49157,
]


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Perform TCP port scan on target.

    Params:
        target: IP address or hostname
        ports: Port specification (e.g. "1-1024", "80,443,8080", "top100")
        timeout: Connection timeout in seconds (default: 1)
        threads: Number of concurrent threads (default: 50)
    """
    target = params.get("target", "")
    ports_spec = params.get("ports", "top100")
    timeout = float(params.get("timeout", 1))
    threads = int(params.get("threads", 50))

    if not target:
        print("[ERROR] No target specified")
        return {"error": "No target specified", "ports": []}

    # Resolve hostname
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(f"[*] Resolved {target} -> {ip}")
    except socket.gaierror as e:
        print(f"[ERROR] Cannot resolve {target}: {e}")
        return {"error": f"Cannot resolve: {e}", "ports": []}

    # Parse port specification
    ports = _parse_ports(ports_spec)
    total = len(ports)

    print(f"[*] Port scan starting on {target} ({ip})")
    print(f"[*] Scanning {total} port(s) with {threads} threads, {timeout}s timeout")
    print("=" * 60)

    open_ports = []
    scanned = 0

    def scan_port(port: int) -> Tuple[int, bool, str]:
        if is_cancelled and is_cancelled():
            return (port, False, "")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Try banner grab
                banner = _grab_banner(sock, port)
                sock.close()
                return (port, True, banner)
            sock.close()
        except Exception:
            pass
        return (port, False, "")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, p): p for p in ports}

        for future in concurrent.futures.as_completed(futures):
            if is_cancelled and is_cancelled():
                executor.shutdown(wait=False, cancel_futures=True)
                print("\n[!] Scan cancelled")
                break

            port, is_open, banner = future.result()
            scanned += 1

            if is_open:
                service = COMMON_SERVICES.get(port, "unknown")
                entry = {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                }
                open_ports.append(entry)
                banner_str = f" [{banner}]" if banner else ""
                print(f"  [+] {port}/tcp  OPEN  {service}{banner_str}")

            if on_progress and scanned % 10 == 0:
                on_progress(scanned, total)

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])

    print("=" * 60)
    print(f"[*] Scan complete: {len(open_ports)} open port(s) found out of {total} scanned")

    if open_ports:
        print(f"\n{'PORT':<12} {'STATE':<10} {'SERVICE':<16} {'BANNER'}")
        print("-" * 60)
        for p in open_ports:
            banner = p['banner'][:30] if p['banner'] else ""
            print(f"  {p['port']}/tcp    {'open':<10} {p['service']:<16} {banner}")

    return {
        "target": target,
        "ip": ip,
        "total_scanned": total,
        "open_count": len(open_ports),
        "ports": open_ports,
    }


def _parse_ports(spec: str) -> List[int]:
    """Parse port specification into list of port numbers."""
    spec = spec.strip().lower()

    if spec == "top100":
        return list(TOP_100_PORTS)
    if spec == "all":
        return list(range(1, 65536))

    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            for p in range(int(start), int(end) + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)

    return sorted(ports)


def _grab_banner(sock: socket.socket, port: int) -> str:
    """Try to grab a service banner."""
    try:
        sock.settimeout(2)
        # Some services need a nudge
        if port in (80, 8080, 8443, 443):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 25:
            pass  # SMTP sends banner automatically
        else:
            sock.send(b"\r\n")

        banner = sock.recv(256)
        return banner.decode("utf-8", errors="ignore").strip().split("\n")[0][:100]
    except Exception:
        return ""
