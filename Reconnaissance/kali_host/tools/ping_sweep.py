"""
Ping Sweep - Host discovery via ICMP ping.
Wraps native ping command or uses raw sockets.
"""
import subprocess
import platform
import ipaddress
import re
from typing import Dict, Any, Callable, Optional


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Perform a ping sweep on a target range.

    Params:
        target: IP address or CIDR range (e.g. "192.168.1.0/24")
        timeout: Timeout per host in seconds (default: 1)
    """
    target = params.get("target", "")
    timeout = int(params.get("timeout", 1))

    if not target:
        print("[ERROR] No target specified")
        return {"error": "No target specified", "hosts": []}

    # Parse target into individual IPs
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            hosts = list(network.hosts())
        else:
            hosts = [ipaddress.ip_address(target)]
    except ValueError as e:
        print(f"[ERROR] Invalid target: {e}")
        return {"error": str(e), "hosts": []}

    total = len(hosts)
    alive_hosts = []
    is_windows = platform.system().lower() == "windows"

    print(f"[*] Ping sweep starting on {target}")
    print(f"[*] Scanning {total} host(s) with {timeout}s timeout")
    print("-" * 50)

    for i, host in enumerate(hosts):
        if is_cancelled and is_cancelled():
            print("\n[!] Scan cancelled by user")
            break

        ip_str = str(host)

        # Build ping command per platform
        if is_windows:
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip_str]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip_str]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 2,
            )
            if result.returncode == 0:
                # Extract RTT
                rtt = _extract_rtt(result.stdout, is_windows)
                alive_hosts.append({"ip": ip_str, "rtt_ms": rtt})
                print(f"  [+] {ip_str} is ALIVE (RTT: {rtt}ms)")
            else:
                # Only print if scanning a small range
                if total <= 10:
                    print(f"  [-] {ip_str} no response")

        except subprocess.TimeoutExpired:
            if total <= 10:
                print(f"  [-] {ip_str} timed out")
        except Exception as e:
            print(f"  [!] {ip_str} error: {e}")

        if on_progress:
            on_progress(i + 1, total)

    print("-" * 50)
    print(f"[*] Sweep complete: {len(alive_hosts)}/{total} hosts alive")

    return {
        "target": target,
        "total_scanned": total,
        "alive_count": len(alive_hosts),
        "hosts": alive_hosts,
    }


def _extract_rtt(output: str, is_windows: bool) -> float:
    """Extract average RTT from ping output."""
    try:
        if is_windows:
            match = re.search(r"Average\s*=\s*(\d+)ms", output)
        else:
            match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", output)
        if match:
            return float(match.group(1))
    except Exception:
        pass
    return -1.0
