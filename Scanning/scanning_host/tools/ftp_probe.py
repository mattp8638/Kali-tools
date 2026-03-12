from ftplib import FTP
from typing import Any, Dict

from scanning_host.core.common import normalize_host, safe_int


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    host = normalize_host(params.get("target", ""))
    port = safe_int(params.get("port", 21), 21)
    timeout = int(params.get("timeout", 5))

    if not host:
        return {"error": "target is required"}

    print("[*] FTP probe starting")
    print(f"[*] Target: {host}:{port}")

    result: Dict[str, Any] = {"target": host, "port": port}
    ftp = FTP()
    try:
        ftp.connect(host=host, port=port, timeout=timeout)
        result["banner"] = ftp.getwelcome()
        print(f"[+] Banner: {result['banner']}")

        anon_ok = False
        try:
            ftp.login("anonymous", "anonymous@local")
            anon_ok = True
            result["anonymous_login"] = True
            print("[+] Anonymous login allowed")
            result["cwd"] = ftp.pwd()
            listing = []
            ftp.retrlines("LIST", listing.append)
            result["listing_preview"] = listing[:20]
        except Exception as e:
            result["anonymous_login"] = False
            result["anonymous_error"] = str(e)
            print(f"[-] Anonymous login denied: {e}")

        if not anon_ok and params.get("username"):
            try:
                ftp.login(params.get("username"), params.get("password", ""))
                result["credential_login"] = True
                print("[+] Credential login succeeded")
            except Exception as e:
                result["credential_login"] = False
                result["credential_error"] = str(e)
                print(f"[-] Credential login failed: {e}")
    except Exception as e:
        result["error"] = str(e)
        print(f"[!] FTP probe failed: {e}")
    finally:
        try:
            ftp.quit()
        except Exception:
            pass

    print("[*] FTP probe complete")
    return result
