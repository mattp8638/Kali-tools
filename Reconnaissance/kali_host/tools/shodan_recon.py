"""
Shodan Recon - Host lookup and internet-wide search.
Requires a Shodan API key (param, env var, or stored API key manager).
"""
from typing import Dict, Any, Callable
import os
import socket
from kali_host.core.api_keys import get_api_key_manager


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run Shodan host lookup or search query.

    Params:
        ip_or_domain: Single host (IP or hostname) to look up via Shodan.host()
        query: Shodan search query (e.g. org:"Acme Corp" port:443)
        api_key: Shodan API key (falls back to SHODAN_API_KEY env var)
    """
    ip_or_domain = params.get("ip_or_domain", "").strip()
    query = params.get("query", "").strip()
    api_key = params.get("api_key", "").strip() or _get_stored_key() or _get_env_key()

    if not api_key:
        print("[ERROR] No Shodan API key provided")
        print("[*] Add via Settings, or pass it in the api_key field,")
        print("[*] or set the SHODAN_API_KEY environment variable.")
        return {"error": "No Shodan API key provided"}

    if not ip_or_domain and not query:
        print("[ERROR] You must provide either ip_or_domain or a search query")
        return {"error": "Missing ip_or_domain or query"}

    try:
        import shodan
    except ImportError:
        print("[ERROR] Shodan Python library not installed")
        print("[*] Run: pip install shodan")
        return {"error": "shodan package not installed"}

    api = shodan.Shodan(api_key)
    results: Dict[str, Any] = {"mode": None}

    try:
        if ip_or_domain:
            results["mode"] = "host"
            ip = _resolve_ip(ip_or_domain)
            print(f"[*] Shodan host lookup for: {ip_or_domain}")
            if ip != ip_or_domain:
                print(f"[*] Resolved to: {ip}")
            print("=" * 60)

            if is_cancelled and is_cancelled():
                return results

            host = api.host(ip)
            _print_host(host)

            if on_progress:
                on_progress(1, 1)

            results["host"] = _host_to_dict(host)

        else:
            results["mode"] = "search"
            print(f"[*] Shodan search: {query}")
            print("=" * 60)

            if is_cancelled and is_cancelled():
                return results

            res = api.search(query, page=1)
            _print_search(res)

            if on_progress:
                on_progress(1, 1)

            results["query"] = query
            results["total"] = res.get("total", 0)
            results["matches"] = [
                {
                    "ip": m.get("ip_str"),
                    "port": m.get("port"),
                    "org": m.get("org"),
                    "product": m.get("product"),
                    "location": m.get("location", {}),
                }
                for m in res.get("matches", [])
            ]

    except shodan.APIError as e:
        print(f"[ERROR] Shodan API error: {e}")
        return {"error": str(e)}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}

    print("=" * 60)
    print("[*] Shodan recon complete")
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_stored_key() -> str:
    """Get Shodan API key from APIKeyManager."""
    try:
        mgr = get_api_key_manager()
        return mgr.get_key("shodan") or ""
    except Exception:
        return ""


def _get_env_key() -> str:
    return os.environ.get("SHODAN_API_KEY", "")


def _resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host


def _print_host(host: Dict[str, Any]) -> None:
    print(f"[+] IP:       {host.get('ip_str')}")
    print(f"    Org:      {host.get('org', 'N/A')}")
    print(f"    OS:       {host.get('os', 'N/A')}")
    print(f"    Country:  {host.get('country_name', 'N/A')}")
    print(f"    ASN:      {host.get('asn', 'N/A')}")
    hostnames = host.get("hostnames", [])
    if hostnames:
        print(f"    Hostnames: {', '.join(hostnames[:5])}")

    print(f"\n[*] Open ports ({len(host.get('data', []))}):")
    for item in host.get("data", []):
        product = item.get("product") or ""
        version = item.get("version") or ""
        service = item.get("transport", "tcp")
        banner = f"  {product} {version}".strip()
        print(f"  - {item.get('port')}/{service}  {banner}")

    tags = host.get("tags", [])
    if tags:
        print(f"\n[*] Tags: {', '.join(tags)}")

    vulns = host.get("vulns", {})
    if vulns:
        print(f"\n[!] Vulnerabilities ({len(vulns)}):")
        for cve in list(vulns.keys())[:10]:
            print(f"  - {cve}")


def _host_to_dict(host: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ip": host.get("ip_str"),
        "org": host.get("org"),
        "os": host.get("os"),
        "country": host.get("country_name"),
        "asn": host.get("asn"),
        "hostnames": host.get("hostnames", []),
        "tags": host.get("tags", []),
        "vulns": list(host.get("vulns", {}).keys()),
        "ports": [
            {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "info": item.get("info"),
                "cpe": item.get("cpe"),
            }
            for item in host.get("data", [])
        ],
    }


def _print_search(res: Dict[str, Any]) -> None:
    total = res.get("total", 0)
    matches = res.get("matches", [])
    print(f"[*] Total matches: {total}")
    print(f"[*] Showing first {len(matches)} result(s)")
    print()
    for m in matches[:20]:
        ip = m.get("ip_str", "?")
        port = m.get("port", "?")
        org = m.get("org") or ""
        product = m.get("product") or ""
        country = (m.get("location") or {}).get("country_name", "")
        print(f"  - {ip}:{port}  {org}  {product}  [{country}]")
