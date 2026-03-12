"""
DNS Recon - DNS enumeration and lookup tool.
Uses Python's dns.resolver (dnspython) or falls back to system nslookup.
"""
import socket
import subprocess
import platform
from typing import Dict, Any, Callable, Optional, List


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Perform DNS reconnaissance on a target domain.

    Params:
        target: Domain name (e.g. "example.com")
        record_types: Comma-separated DNS record types (default: "A,AAAA,MX,NS,TXT,SOA,CNAME")
        nameserver: Optional nameserver to use
    """
    target = params.get("target", "")
    record_types_str = params.get("record_types", "A,AAAA,MX,NS,TXT,SOA,CNAME")
    nameserver = params.get("nameserver", "")

    if not target:
        print("[ERROR] No target domain specified")
        return {"error": "No target domain specified", "records": {}}

    record_types = [r.strip().upper() for r in record_types_str.split(",")]
    results = {"domain": target, "records": {}, "reverse_dns": []}

    print(f"[*] DNS Recon starting for: {target}")
    if nameserver:
        print(f"[*] Using nameserver: {nameserver}")
    print(f"[*] Record types: {', '.join(record_types)}")
    print("=" * 60)

    # Try dnspython first, fall back to socket/nslookup
    try:
        import dns.resolver
        results["records"] = _resolve_with_dnspython(
            target, record_types, nameserver, on_progress, is_cancelled
        )
    except ImportError:
        print("[*] dnspython not installed, using system lookups")
        results["records"] = _resolve_with_system(
            target, record_types, on_progress, is_cancelled
        )

    # Reverse DNS on any A records found
    if is_cancelled and is_cancelled():
        print("\n[!] Scan cancelled")
        return results

    a_records = results["records"].get("A", [])
    if a_records:
        print("\n--- Reverse DNS ---")
        for ip in a_records:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                results["reverse_dns"].append({"ip": ip, "hostname": hostname})
                print(f"  {ip} -> {hostname}")
            except socket.herror:
                print(f"  {ip} -> (no reverse record)")

    # Basic whois-style info via socket
    print("\n--- Host Resolution ---")
    try:
        addrs = socket.getaddrinfo(target, None)
        unique_ips = set()
        for addr in addrs:
            ip = addr[4][0]
            if ip not in unique_ips:
                unique_ips.add(ip)
                family = "IPv6" if addr[0] == socket.AF_INET6 else "IPv4"
                print(f"  {family}: {ip}")
    except socket.gaierror as e:
        print(f"  [!] Resolution failed: {e}")

    print("=" * 60)
    total_records = sum(len(v) for v in results["records"].values())
    print(f"[*] DNS Recon complete: {total_records} record(s) found")

    return results


def _resolve_with_dnspython(
    domain: str,
    record_types: List[str],
    nameserver: str,
    on_progress: Callable,
    is_cancelled: Callable,
) -> Dict[str, List[str]]:
    """Resolve using dnspython library."""
    import dns.resolver

    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]

    records = {}
    total = len(record_types)

    for i, rtype in enumerate(record_types):
        if is_cancelled and is_cancelled():
            break

        print(f"\n--- {rtype} Records ---")
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = []
            for rdata in answers:
                value = str(rdata)
                records[rtype].append(value)
                print(f"  {rtype}: {value}")
        except dns.resolver.NoAnswer:
            print(f"  (no {rtype} records)")
        except dns.resolver.NXDOMAIN:
            print(f"  [!] Domain {domain} does not exist")
            break
        except dns.resolver.NoNameservers:
            print(f"  [!] No nameservers available for {rtype}")
        except Exception as e:
            print(f"  [!] Error querying {rtype}: {e}")

        if on_progress:
            on_progress(i + 1, total)

    return records


def _resolve_with_system(
    domain: str,
    record_types: List[str],
    on_progress: Callable,
    is_cancelled: Callable,
) -> Dict[str, List[str]]:
    """Fallback: resolve using system nslookup/dig."""
    records = {}
    total = len(record_types)
    is_windows = platform.system().lower() == "windows"

    for i, rtype in enumerate(record_types):
        if is_cancelled and is_cancelled():
            break

        print(f"\n--- {rtype} Records ---")

        if is_windows:
            cmd = ["nslookup", "-type=" + rtype, domain]
        else:
            cmd = ["dig", "+short", rtype, domain]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout.strip()
            if output:
                lines = [l.strip() for l in output.split("\n") if l.strip()]
                records[rtype] = lines
                for line in lines:
                    print(f"  {line}")
            else:
                print(f"  (no {rtype} records)")
        except Exception as e:
            print(f"  [!] Error: {e}")

        if on_progress:
            on_progress(i + 1, total)

    return records
