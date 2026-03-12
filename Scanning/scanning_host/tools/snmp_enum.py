from typing import Any, Dict, List

from scanning_host.core.common import normalize_host, safe_int


COMMON_STRINGS = ["public", "private", "community", "snmp", "manager", "read"]


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    host = normalize_host(params.get("target", ""))
    port = safe_int(params.get("port", 161), 161)
    timeout = int(params.get("timeout", 2))

    if not host:
        return {"error": "target is required"}

    try:
        from pysnmp.hlapi import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            getCmd,
            nextCmd,
        )
    except Exception as e:
        try:
            from pysnmp.hlapi.asyncore import (
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                getCmd,
                nextCmd,
            )
        except Exception:
            return {"error": f"pysnmp not available: {e}"}

    communities = params.get("communities", "")
    test_strings = [s.strip() for s in communities.split(",") if s.strip()] if communities else COMMON_STRINGS

    working = None
    sysinfo: Dict[str, str] = {}

    for idx, c in enumerate(test_strings, start=1):
        if is_cancelled and is_cancelled():
            break
        if on_progress:
            on_progress(idx, len(test_strings))

        iterator = getCmd(
            SnmpEngine(),
            CommunityData(c, mpModel=1),
            UdpTransportTarget((host, port), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        )
        error_indication, error_status, _, var_binds = next(iterator)
        if not error_indication and not error_status:
            working = c
            for n, v in var_binds:
                sysinfo[str(n)] = str(v)
            break

    if not working:
        return {"target": host, "port": port, "working_community": None, "error": "No working community found"}

    walk_rows: List[Dict[str, str]] = []
    try:
        for (error_indication, error_status, _, var_binds) in nextCmd(
            SnmpEngine(),
            CommunityData(working, mpModel=1),
            UdpTransportTarget((host, port), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1")),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for n, v in var_binds:
                walk_rows.append({"oid": str(n), "value": str(v)})
                if len(walk_rows) >= 50:
                    raise StopIteration
    except StopIteration:
        pass

    return {
        "target": host,
        "port": port,
        "working_community": working,
        "sysinfo": sysinfo,
        "walk_preview": walk_rows,
        "walk_count": len(walk_rows),
    }
