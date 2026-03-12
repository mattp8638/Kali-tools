import socket
import struct
from typing import Any, Dict

from scanning_host.core.common import normalize_host, safe_int


# TPKT + X.224 + RDP Negotiation Request (request SSL + CredSSP/NLA).
RDP_NEG_REQ = bytes.fromhex("030000130ee000000000000100080003000000")


def _parse_rdp_neg_response(data: bytes) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "response_hex": data.hex(),
        "nla_enforced": None,
        "selected_protocol": None,
        "selected_protocol_name": None,
        "failure_code": None,
    }

    if len(data) < 19:
        return result

    msg_type = data[11]
    if msg_type == 0x02:
        selected = struct.unpack("<I", data[15:19])[0]
        names = {
            0: "RDP",
            1: "SSL",
            2: "HYBRID (NLA)",
            8: "HYBRID_EX (NLA)",
        }
        result["selected_protocol"] = selected
        result["selected_protocol_name"] = names.get(selected, f"UNKNOWN({selected})")
        result["nla_enforced"] = selected in {2, 8}
    elif msg_type == 0x03:
        result["failure_code"] = struct.unpack("<I", data[15:19])[0]

    return result


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    host = normalize_host(params.get("target", ""))
    port = safe_int(params.get("port", 3389), 3389)
    timeout = float(params.get("timeout", 5))

    if not host:
        return {"error": "target is required"}

    result: Dict[str, Any] = {"target": host, "port": port}

    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(RDP_NEG_REQ)
        data = sock.recv(4096)

        parsed = _parse_rdp_neg_response(data)
        result.update(parsed)
        result["rdp_reachable"] = True

        if parsed.get("nla_enforced") is False:
            result["finding"] = "RDP reachable but NLA may not be enforced"
    except Exception as e:
        result["rdp_reachable"] = False
        result["error"] = str(e)
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass

    return result
