from typing import Any, Dict, List


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    target_cidr = str(params.get("target", "")).strip()
    timeout = float(params.get("timeout", 2))

    if not target_cidr:
        return {"error": "target CIDR is required (e.g. 192.168.1.0/24)"}

    try:
        from scapy.all import ARP, Ether, srp
    except Exception as e:
        return {"error": f"scapy not available: {e}"}

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_cidr)
    answered, _ = srp(packet, timeout=timeout, verbose=0)

    hosts: List[Dict[str, str]] = []
    for _, recv in answered:
        hosts.append({"ip": recv.psrc, "mac": recv.hwsrc})

    hosts.sort(key=lambda x: x["ip"])
    return {"target": target_cidr, "host_count": len(hosts), "hosts": hosts}
