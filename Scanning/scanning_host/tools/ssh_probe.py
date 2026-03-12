from typing import Any, Dict, List

from scanning_host.core.common import normalize_host, safe_int


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    host = normalize_host(params.get("target", ""))
    port = safe_int(params.get("port", 22), 22)
    timeout = int(params.get("timeout", 5))

    if not host:
        return {"error": "target is required"}

    try:
        import paramiko
        from paramiko.transport import Transport
    except Exception as e:
        return {"error": f"paramiko not available: {e}"}

    result: Dict[str, Any] = {"target": host, "port": port}

    sock = None
    transport = None
    try:
        import socket

        sock = socket.create_connection((host, port), timeout=timeout)
        transport = Transport(sock)
        transport.start_client(timeout=timeout)

        server_key = transport.get_remote_server_key()
        sec = transport.get_security_options()

        result["server_version"] = transport.remote_version
        result["host_key_type"] = server_key.get_name() if server_key else "unknown"
        result["kex"] = list(sec.kex)
        result["ciphers"] = list(sec.ciphers)
        result["digests"] = list(sec.digests)

        weak = [c for c in sec.ciphers if c.lower() in {"3des-cbc", "blowfish-cbc", "aes128-cbc", "arcfour"}]
        result["weak_ciphers"] = weak
    except Exception as e:
        result["error"] = str(e)
    finally:
        try:
            if transport:
                transport.close()
        except Exception:
            pass
        try:
            if sock:
                sock.close()
        except Exception:
            pass

    return result
