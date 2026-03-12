"""
WHOIS Lookup - Domain/IP registration information.
Uses python-whois or falls back to system whois command.
"""
import subprocess
import platform
from typing import Dict, Any, Callable


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Perform WHOIS lookup on target.

    Params:
        target: Domain name or IP address
    """
    target = params.get("target", "")

    if not target:
        print("[ERROR] No target specified")
        return {"error": "No target specified"}

    print(f"[*] WHOIS lookup for: {target}")
    print("=" * 60)

    # Try python-whois first
    try:
        import whois
        return _lookup_with_python_whois(target)
    except ImportError:
        print("[*] python-whois not installed, using system whois")
        return _lookup_with_system(target)


def _lookup_with_python_whois(target: str) -> Dict[str, Any]:
    """Use python-whois library."""
    import whois

    try:
        w = whois.whois(target)

        info = {
            "domain": target,
            "registrar": w.registrar or "N/A",
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "updated_date": str(w.updated_date) if w.updated_date else "N/A",
            "name_servers": w.name_servers if w.name_servers else [],
            "status": w.status if w.status else [],
            "registrant": w.org or w.name or "N/A",
            "country": w.country or "N/A",
            "emails": w.emails if w.emails else [],
        }

        print(f"  Domain:      {info['domain']}")
        print(f"  Registrar:   {info['registrar']}")
        print(f"  Created:     {info['creation_date']}")
        print(f"  Expires:     {info['expiration_date']}")
        print(f"  Updated:     {info['updated_date']}")
        print(f"  Registrant:  {info['registrant']}")
        print(f"  Country:     {info['country']}")

        if info["name_servers"]:
            print(f"  Nameservers:")
            for ns in info["name_servers"]:
                print(f"    - {ns}")

        if info["emails"]:
            print(f"  Emails:")
            for email in info["emails"]:
                print(f"    - {email}")

        print("=" * 60)
        print("[*] WHOIS lookup complete")

        return info

    except Exception as e:
        print(f"[ERROR] WHOIS lookup failed: {e}")
        return {"error": str(e)}


def _lookup_with_system(target: str) -> Dict[str, Any]:
    """Fallback: use system whois command."""
    is_windows = platform.system().lower() == "windows"

    try:
        if is_windows:
            # Windows doesn't have whois by default, try nslookup as fallback
            cmd = ["nslookup", target]
        else:
            cmd = ["whois", target]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )

        output = result.stdout
        print(output)
        print("=" * 60)
        print("[*] WHOIS lookup complete")

        return {"domain": target, "raw_output": output}

    except FileNotFoundError:
        print("[!] whois command not found on this system")
        print("[*] Install python-whois: pip install python-whois")
        return {"error": "whois command not found"}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}
