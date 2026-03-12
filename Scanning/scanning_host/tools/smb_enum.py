from typing import Any, Dict

from scanning_host.core.common import normalize_host, safe_int


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    host = normalize_host(params.get("target", ""))
    username = params.get("username", "")
    password = params.get("password", "")
    domain = params.get("domain", "")
    port = safe_int(params.get("port", 445), 445)

    if not host:
        return {"error": "target is required"}

    try:
        from impacket.smbconnection import SMBConnection
    except Exception as e:
        return {"error": f"impacket not available: {e}"}

    conn = SMBConnection(remoteName=host, remoteHost=host, sess_port=port, timeout=5)
    auth_mode = "anonymous"
    try:
        if username:
            conn.login(username, password, domain)
            auth_mode = "credentials"
        else:
            conn.login("", "")
    except Exception as e:
        return {"target": host, "error": f"SMB login failed: {e}"}

    shares = []
    try:
        for s in conn.listShares():
            name = s["shi1_netname"].rstrip("\x00")
            shares.append({"name": name, "remark": s["shi1_remark"].rstrip("\x00")})
    except Exception:
        pass

    server_os = ""
    try:
        server_os = conn.getServerOS()
    except Exception:
        pass

    details: Dict[str, Any] = {}
    for method_name, key in (
        ("getServerName", "server_name"),
        ("getServerDomain", "server_domain"),
        ("getServerDNSDomainName", "dns_domain"),
        ("getServerDNSHostName", "dns_hostname"),
    ):
        try:
            value = getattr(conn, method_name)()
            details[key] = value
        except Exception:
            pass

    try:
        details["dialect"] = conn.getDialect()
    except Exception:
        pass

    try:
        details["signing_required"] = bool(conn.isSigningRequired())
    except Exception:
        details["signing_required"] = None

    share_previews = []
    for share in shares:
        if len(share_previews) >= 5:
            break
        share_name = share.get("name", "")
        if share_name.endswith("$"):
            continue
        try:
            entries = conn.listPath(share_name, "*")
            files = []
            for item in entries[:20]:
                filename = item.get_longname()
                if filename in {".", ".."}:
                    continue
                files.append({
                    "name": filename,
                    "is_dir": bool(item.is_directory()),
                    "size": int(item.get_filesize()),
                })
            share_previews.append({"share": share_name, "entries": files})
        except Exception:
            continue

    conn.close()
    return {
        "target": host,
        "auth_mode": auth_mode,
        "server_os": server_os,
        "server_details": details,
        "share_count": len(shares),
        "shares": shares,
        "share_previews": share_previews,
    }
