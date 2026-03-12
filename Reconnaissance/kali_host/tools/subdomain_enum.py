"""
Subdomain Enumeration - Discover subdomains via DNS brute-force and certificate transparency.
"""
import socket
import concurrent.futures
from typing import Dict, Any, Callable, List


# Common subdomain wordlist
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "dns", "dns1", "dns2",
    "webmail", "cpanel", "whm", "autodiscover", "autoconfig",
    "mx", "imap", "blog", "dev", "staging", "stage", "test", "testing",
    "api", "app", "admin", "portal", "secure", "vpn", "remote",
    "cloud", "cdn", "static", "assets", "media", "images", "img",
    "docs", "doc", "help", "support", "status", "monitor",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo",
    "shop", "store", "cart", "pay", "payment", "billing",
    "m", "mobile", "wap",
    "intranet", "internal", "corp", "office", "exchange",
    "proxy", "gateway", "firewall", "router",
    "backup", "bak", "old", "new", "v2", "beta", "alpha",
    "demo", "sandbox", "preview", "uat",
    "login", "sso", "auth", "oauth", "id", "identity",
    "dashboard", "panel", "console", "manage",
    "ws", "socket", "realtime", "push",
    "analytics", "metrics", "grafana", "kibana", "elk",
    "s3", "storage", "files", "upload",
    "www1", "www2", "web", "web1", "web2",
    "ns3", "ns4", "mx1", "mx2",
]


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Enumerate subdomains for a target domain.

    Params:
        target: Domain name (e.g. "example.com")
        threads: Number of concurrent threads (default: 20)
        timeout: DNS timeout in seconds (default: 2)
        use_ct: Check certificate transparency logs (default: true)
    """
    target = params.get("target", "")
    threads = int(params.get("threads", 20))
    timeout = float(params.get("timeout", 2))
    use_ct = params.get("use_ct", True)

    if not target:
        print("[ERROR] No target domain specified")
        return {"error": "No target domain specified", "subdomains": []}

    # Remove any leading dots or www
    target = target.lstrip(".")
    if target.startswith("www."):
        target = target[4:]

    print(f"[*] Subdomain enumeration for: {target}")
    print(f"[*] Wordlist: {len(COMMON_SUBDOMAINS)} entries, {threads} threads")
    print("=" * 60)

    found_subdomains = []
    scanned = 0
    total = len(COMMON_SUBDOMAINS)

    # DNS brute force
    print("\n--- DNS Brute Force ---")

    def check_subdomain(sub: str) -> Dict[str, Any]:
        fqdn = f"{sub}.{target}"
        try:
            socket.setdefaulttimeout(timeout)
            ips = socket.gethostbyname_ex(fqdn)
            return {
                "subdomain": fqdn,
                "prefix": sub,
                "ips": ips[2],
                "source": "dns_bruteforce",
            }
        except (socket.gaierror, socket.timeout, OSError):
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_subdomain, sub): sub
            for sub in COMMON_SUBDOMAINS
        }

        for future in concurrent.futures.as_completed(futures):
            if is_cancelled and is_cancelled():
                executor.shutdown(wait=False, cancel_futures=True)
                print("\n[!] Scan cancelled")
                break

            scanned += 1
            result = future.result()
            if result:
                found_subdomains.append(result)
                ips = ", ".join(result["ips"])
                print(f"  [+] {result['subdomain']} -> {ips}")

            if on_progress:
                on_progress(scanned, total)

    # Certificate Transparency (via crt.sh)
    if use_ct and not (is_cancelled and is_cancelled()):
        print("\n--- Certificate Transparency (crt.sh) ---")
        ct_results = _check_ct_logs(target)
        for ct in ct_results:
            # Avoid duplicates
            if not any(s["subdomain"] == ct["subdomain"] for s in found_subdomains):
                found_subdomains.append(ct)
                print(f"  [+] {ct['subdomain']} (from CT logs)")

    # Sort results
    found_subdomains.sort(key=lambda x: x["subdomain"])

    print("=" * 60)
    print(f"[*] Enumeration complete: {len(found_subdomains)} subdomain(s) found")

    if found_subdomains:
        print(f"\n{'SUBDOMAIN':<40} {'IPs':<30} {'SOURCE'}")
        print("-" * 80)
        for s in found_subdomains:
            ips = ", ".join(s.get("ips", ["N/A"]))
            print(f"  {s['subdomain']:<38} {ips:<30} {s['source']}")

    return {
        "domain": target,
        "total_checked": total,
        "found_count": len(found_subdomains),
        "subdomains": found_subdomains,
    }


def _check_ct_logs(domain: str) -> List[Dict[str, Any]]:
    """Query crt.sh certificate transparency logs."""
    import urllib.request
    import json

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "KaliAppHost/1.0"})
        response = urllib.request.urlopen(req, timeout=15)
        data = json.loads(response.read())

        subdomains = set()
        results = []
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}") and sub not in subdomains:
                    if "*" not in sub:
                        subdomains.add(sub)
                        results.append({
                            "subdomain": sub,
                            "prefix": sub.replace(f".{domain}", ""),
                            "ips": [],
                            "source": "ct_logs",
                        })

        print(f"  [*] Found {len(results)} unique subdomain(s) from CT logs")
        return results

    except Exception as e:
        print(f"  [!] CT log check failed: {e}")
        return []
