from typing import Any, Dict, List

from scanning_host.core.common import normalize_host, safe_int


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    target = normalize_host(params.get("target", ""))
    max_hops = safe_int(params.get("max_hops", 20), 20)
    timeout = float(params.get("timeout", 2))

    if not target:
        return {"error": "target is required"}

    print("[*] Traceroute starting")
    print(f"[*] Target: {target}")
    print(f"[*] Max hops: {max_hops} | Timeout: {timeout}s")

    try:
        from scapy.all import IP, ICMP, sr1
    except Exception as e:
        return {"error": f"scapy not available: {e}"}

    hops: List[Dict[str, Any]] = []

    for ttl in range(1, max_hops + 1):
        if is_cancelled and is_cancelled():
            break
        if on_progress:
            on_progress(ttl, max_hops)

        pkt = IP(dst=target, ttl=ttl) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply is None:
            hops.append({"ttl": ttl, "ip": "*", "status": "timeout"})
            print(f"[-] ttl={ttl} -> timeout")
            continue

        hop_ip = reply.src
        hops.append({"ttl": ttl, "ip": hop_ip, "status": "ok"})
        print(f"[+] ttl={ttl} -> {hop_ip}")
        if hop_ip == target:
            break

    print(f"[*] Traceroute complete: {len(hops)} hop(s)")
    return {"target": target, "hops": hops, "hop_count": len(hops)}
