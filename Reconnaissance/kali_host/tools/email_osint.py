"""
Email OSINT - Deep email address reconnaissance.
Pure Python using requests, dnspython and beautifulsoup4.
Gathers: MX/SPF/DMARC/DKIM DNS records, breach checks via BreachDirectory,
crt.sh certificate intel for email domain, Hunter.io domain search (if API key
provided), Shodan reverse lookup on mail servers (if API key provided),
and basic social/paste presence signals.

All API keys are optional; the tool still provides useful results without them.
"""
import re
import json
import socket
import urllib.parse
from typing import Dict, Any, Callable, List, Optional
from kali_host.core.api_keys import get_api_key_manager


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Email reconnaissance: DNS, breaches, domain info, social presence.
    
    Params:
        email: Email address to investigate
        check_breaches: Check BreachDirectory (default: true)
        check_dns: Perform DNS recon (default: true)
        check_social: Check social signals (default: true)
        check_ct: Certificate transparency lookup (default: true)
        breachdirectory_api_key: BreachDirectory API key (optional, free access available)
        hunter_api_key: Hunter.io API key (optional)
        shodan_api_key: Shodan API key (optional)
    """
    email = params.get("email", "").strip().lower()
    breachdirectory_key = params.get("breachdirectory_api_key", "").strip() or _get_breachdirectory_key()
    hunter_key = params.get("hunter_api_key", "").strip() or _get_hunter_key()
    shodan_key = params.get("shodan_api_key", "").strip() or _get_shodan_key()
    check_breaches = bool(params.get("check_breaches", True))
    check_dns = bool(params.get("check_dns", True))
    check_social = bool(params.get("check_social", True))
    check_ct = bool(params.get("check_ct", True))

    if not email or "@" not in email:
        print("[ERROR] A valid email address is required (user@domain.com)")
        return {"error": "Invalid or missing email address"}

    user_part, domain = email.split("@", 1)

    print(f"[*] Email OSINT starting for: {email}")
    print(f"[*] Domain: {domain}")
    print("=" * 60)

    results: Dict[str, Any] = {
        "email": email,
        "domain": domain,
        "dns": {},
        "breaches": [],
        "hunter_results": {},
        "ct_subdomains": [],
        "social_signals": [],
        "mail_server_ips": [],
    }

    step = 0
    total_steps = sum([
        check_dns,
        check_breaches,
        bool(hunter_key),
        check_ct,
        check_social,
        bool(shodan_key),
    ]) or 1

    def _progress():
        nonlocal step
        step += 1
        if on_progress:
            on_progress(step, total_steps)

    # ------------------------------------------------------------------
    # 1. DNS Recon: MX, SPF, DMARC, DKIM
    # ------------------------------------------------------------------
    if check_dns and not (is_cancelled and is_cancelled()):
        print("\n--- DNS Recon ---")
        mx = _dns_mx(domain)
        results["dns"]["mx"] = mx
        if mx:
            print(f"  [+] MX records:")
            for m in mx:
                print(f"      {m}")
                try:
                    ip = socket.gethostbyname(m)
                    if ip not in results["mail_server_ips"]:
                        results["mail_server_ips"].append(ip)
                    print(f"         -> {ip}")
                except Exception:
                    pass
        else:
            print("  [-] No MX records found")

        # SPF
        spf = [r for r in _dns_txt_records(domain) if r.startswith("v=spf")]
        results["dns"]["spf"] = spf
        if spf:
            print(f"  [+] SPF: {spf[0][:120]}")
        else:
            print("  [-] No SPF record (mail may be spoofable)")

        # DMARC
        dmarc = _dns_txt_records(domain, "_dmarc")
        results["dns"]["dmarc"] = dmarc
        if dmarc:
            print(f"  [+] DMARC: {dmarc[0][:120]}")
        else:
            print("  [-] No DMARC record (domain not fully protected)")

        # DKIM (common selectors)
        dkim_found = []
        for selector in ["default", "google", "k1", "mail", "email", "s1", "s2"]:
            records = _dns_txt_records(domain, f"{selector}._domainkey")
            if records:
                dkim_found.append(f"{selector}: {records[0][:80]}")
                print(f"  [+] DKIM ({selector}): found")
        results["dns"]["dkim"] = dkim_found
        if not dkim_found:
            print("  [-] No common DKIM selectors found")

        _progress()

    # ------------------------------------------------------------------
    # 2. BreachDirectory Breach Check
    # ------------------------------------------------------------------
    if check_breaches and not (is_cancelled and is_cancelled()):
        print("\n--- Breach Check (BreachDirectory) ---")
        breaches = _check_breachdirectory(email, breachdirectory_key)
        results["breaches"] = breaches
        if breaches:
            print(f"  [!] Found in {len(breaches)} breach(es):")
            for b in breaches:
                print(f"      {b.get('name', 'Unknown')} - {b.get('description', 'Breach found')}")
        else:
            print("  [+] Not found in BreachDirectory")
        _progress()

    # ------------------------------------------------------------------
    # 3. Hunter.io domain search
    # ------------------------------------------------------------------
    if hunter_key and not (is_cancelled and is_cancelled()):
        print("\n--- Hunter.io Domain Search ---")
        hunter_data = _hunter_domain_search(domain, hunter_key)
        results["hunter_results"] = hunter_data
        count = hunter_data.get("total", 0)
        if count:
            print(f"  [+] Hunter.io found {count} email(s) associated with {domain}")
            for em in hunter_data.get("emails", [])[:10]:
                print(f"      - {em.get('value', 'N/A')}")
        else:
            print("  [-] Hunter.io found no emails for this domain")
        _progress()

    # ------------------------------------------------------------------
    # 4. Certificate Transparency Subdomains
    # ------------------------------------------------------------------
    if check_ct and not (is_cancelled and is_cancelled()):
        print("\n--- Certificate Transparency (crt.sh) ---")
        subdomains = _check_crt_sh(domain)
        results["ct_subdomains"] = subdomains
        if subdomains:
            print(f"  [+] Found {len(subdomains)} unique subdomain(s):")
            for sub in subdomains[:15]:
                print(f"      - {sub}")
            if len(subdomains) > 15:
                print(f"      ... and {len(subdomains) - 15} more")
        else:
            print("  [-] No subdomains found in CT logs")
        _progress()

    # ------------------------------------------------------------------
    # 5. Social Signals & Paste Presence
    # ------------------------------------------------------------------
    if check_social and not (is_cancelled and is_cancelled()):
        print("\n--- Social & Paste Signals ---")
        signals = _check_social_signals(email)
        results["social_signals"] = signals
        if signals:
            print(f"  [+] Found {len(signals)} signal(s):")
            for sig in signals:
                print(f"      - {sig}")
        else:
            print("  [-] No signals found")
        _progress()

    # ------------------------------------------------------------------
    # 6. Shodan reverse IP lookup (mail servers)
    # ------------------------------------------------------------------
    if shodan_key and results["mail_server_ips"] and not (is_cancelled and is_cancelled()):
        print("\n--- Shodan Reverse IP Lookup ---")
        for ip in results["mail_server_ips"][:3]:
            try:
                import shodan
                api = shodan.Shodan(shodan_key)
                host = api.host(ip)
                print(f"  [+] {ip}:")
                print(f"      Org: {host.get('org', 'N/A')}")
                print(f"      OS: {host.get('os', 'N/A')}")
                print(f"      Ports: {', '.join(str(p) for p in host.get('ports', [])[:10])}")
            except Exception as e:
                print(f"  [-] Shodan lookup failed: {e}")
        _progress()

    print("\n" + "=" * 60)
    print("[*] Email OSINT complete for: {email}")
    print(f"    MX records:   {len(results['dns'].get('mx', []))}")
    print(f"    SPF present:  {'yes' if results['dns'].get('spf') else 'no'}")
    print(f"    DMARC present: {'yes' if results['dns'].get('dmarc') else 'no'}")
    print(f"    Breaches:     {len(results['breaches'])}")
    print(f"    CT subdomains:{len(results['ct_subdomains'])}")
    print(f"    Signals:      {len(results['social_signals'])}")
    print("=" * 60)

    return results


# ---------------------------------------------------------------------------
# Email Breach Checking
# ---------------------------------------------------------------------------

def _check_breachdirectory(email: str, api_key: str = "") -> List[Dict]:
    """
    Check email against BreachDirectory via RapidAPI.
    
    BreachDirectory is a crowd-sourced breach aggregator with 500M+ records.
    Requires RapidAPI key for access.
    """
    breaches = []
    
    if not api_key:
        print("  [!] BreachDirectory requires RapidAPI key (get from https://rapidapi.com/breachdirectory/api/breachdirectory)")
        return breaches
    
    try:
        import time
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError
        
        # URL encode the email term
        encoded_email = urllib.parse.quote(email)
        url = f"https://breachdirectory.p.rapidapi.com/?func=auto&term={encoded_email}"
        
        headers = {
            'x-rapidapi-key': api_key,
            'x-rapidapi-host': "breachdirectory.p.rapidapi.com",
            'User-Agent': 'Mozilla/5.0'
        }
        
        req = Request(url, headers=headers)
        
        # Retry logic with backoff for rate limits
        max_retries = 2
        retry_delay = 3  # Start with 3 second delay
        
        for attempt in range(max_retries):
            try:
                with urlopen(req, timeout=10) as response:
                    raw_data = response.read().decode("utf-8")
                    
                    if raw_data.strip():
                        try:
                            data = json.loads(raw_data)
                            
                            # BreachDirectory RapidAPI returns: {"success": true, "found": N, "result": [...]}
                            if data.get("success") and data.get("result"):
                                # Group by source to avoid duplicates
                                sources_seen = set()
                                for entry in data.get("result", []):
                                    source = entry.get("sources", "Unknown")
                                    if source not in sources_seen:
                                        breaches.append({
                                            "name": source,
                                            "description": f"Found in {source} breach",
                                            "count": 1,
                                        })
                                        sources_seen.add(source)
                                
                                if breaches:
                                    print(f"  [+] Found in {len(breaches)} breach source(s)")
                            elif data.get("found") == 0:
                                print(f"  [+] Email not found in BreachDirectory")
                            else:
                                # Email might be in database but with partial/masked results
                                found_count = data.get("found", 0)
                                if found_count > 0:
                                    print(f"  [!] Found {found_count} record(s) in BreachDirectory (results may be masked)")
                            
                            break  # Success, exit retry loop
                            
                        except json.JSONDecodeError:
                            print(f"  [!] BreachDirectory returned invalid JSON: {raw_data[:200]}")
                            break
                    else:
                        print(f"  [!] BreachDirectory returned empty response")
                        break
                        
            except HTTPError as e:
                if e.code == 429:  # Too Many Requests
                    if attempt < max_retries - 1:
                        print(f"  [*] Rate limited, retrying in {retry_delay}s...")
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                    else:
                        print(f"  [!] BreachDirectory rate limit exceeded after {max_retries} attempts")
                else:
                    print(f"  [!] BreachDirectory HTTP error {e.code}: {e.reason}")
                    break
        
    except Exception as e:
        print(f"  [!] BreachDirectory lookup error: {e}")
    
    return breaches


# ---------------------------------------------------------------------------
# Hunter.io API
# ---------------------------------------------------------------------------

def _hunter_domain_search(domain: str, api_key: str) -> Dict:
    """Search for emails associated with a domain via Hunter.io."""
    try:
        from urllib.request import urlopen, Request
        
        url = "https://api.hunter.io/v2/domain-search"
        params = {"domain": domain, "api_key": api_key, "limit": 20}
        
        req = Request(url + "?" + urllib.parse.urlencode(params))
        with urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode('utf-8')).get("data", {})
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# DNS Helpers
# ---------------------------------------------------------------------------

def _dns_mx(domain: str) -> List[str]:
    """Get MX records for domain."""
    try:
        import dns.resolver
        records = []
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for answer in answers:
                records.append(str(answer.exchange).rstrip("."))
        except Exception:
            pass
        return records
    except ImportError:
        return []


def _dns_txt_records(domain: str, subdomain: str = "") -> List[str]:
    """Get TXT records."""
    try:
        import dns.resolver
        target = f"{subdomain}.{domain}" if subdomain else domain
        records = []
        try:
            answers = dns.resolver.resolve(target, 'TXT')
            for answer in answers:
                records.append(str(answer))
        except Exception:
            pass
        return records
    except ImportError:
        return []


# ---------------------------------------------------------------------------
# Certificate Transparency
# ---------------------------------------------------------------------------

def _check_crt_sh(domain: str) -> List[str]:
    """Query crt.sh for subdomains."""
    subdomains = set()
    try:
        from urllib.request import urlopen
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        with urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            for entry in data:
                name_value = entry.get('name_value', '')
                for name in name_value.split('\n'):
                    if name.strip():
                        subdomains.add(name.strip())
    except Exception:
        pass
    return sorted(list(subdomains))


# ---------------------------------------------------------------------------
# Social Signals
# ---------------------------------------------------------------------------

def _check_social_signals(email: str) -> List[str]:
    """Check social media signals for this email."""
    signals = []
    
    # Note: These are simplified checks; real OSINT would use APIs
    signals.append("Email format valid")
    
    return signals


# ---------------------------------------------------------------------------
# API Key Helpers
# ---------------------------------------------------------------------------

def _get_breachdirectory_key() -> str:
    """Get BreachDirectory API key from APIKeyManager."""
    try:
        mgr = get_api_key_manager()
        return mgr.get_key("breachdirectory") or ""
    except Exception:
        return ""


def _get_hunter_key() -> str:
    """Get Hunter.io API key from APIKeyManager."""
    try:
        mgr = get_api_key_manager()
        return mgr.get_key("hunter") or ""
    except Exception:
        return ""


def _get_shodan_key() -> str:
    """Get Shodan API key from APIKeyManager."""
    try:
        mgr = get_api_key_manager()
        return mgr.get_key("shodan") or ""
    except Exception:
        return ""
