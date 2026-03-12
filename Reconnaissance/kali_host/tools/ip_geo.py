"""
IP Geolocation & ASN Lookup - Fast bulk IP intelligence.
Uses ip-api.com (free, no key) and ipinfo.io (free tier with key).
Provides country, city, ISP, ASN, lat/lon for any IP or hostname.
"""
import json
import socket
import urllib.parse
from typing import Dict, Any, Callable, List
from kali_host.core.api_keys import get_api_key_manager


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    IP geolocation, ASN, and network intelligence for one or more IPs/hostnames.

    Params:
        targets: Comma-separated IPs or hostnames to look up
        ipinfo_api_key: ipinfo.io API key (optional, increases rate limit)
        resolve_hostnames: Resolve hostnames to IPs first (default: true)
    """
    raw_targets = params.get("targets", "").strip()
    ipinfo_key = params.get("ipinfo_api_key", "").strip() or _get_ipinfo_key()
    resolve = str(params.get("resolve_hostnames", "true")).lower() not in ("false", "0", "no")

    if not raw_targets:
        print("[ERROR] At least one IP address or hostname is required")
        return {"error": "No targets provided"}

    targets = [t.strip() for t in raw_targets.replace("\n", ",").split(",") if t.strip()]

    print(f"[*] IP Geolocation & ASN Lookup")
    print(f"[*] Targets: {len(targets)}")
    print("=" * 60)

    results: Dict[str, Any] = {
        "targets": targets,
        "lookups": [],
        "asns_seen": [],
        "countries_seen": [],
        "cloud_providers_seen": [],
    }

    total = len(targets)

    for i, target in enumerate(targets):
        if is_cancelled and is_cancelled():
            break
        if on_progress:
            on_progress(i + 1, total)

        print(f"\n[{i+1}/{total}] {target}")

        ip = target
        # Resolve hostname if needed
        if resolve and not _is_ip(target):
            try:
                ip = socket.gethostbyname(target)
                print(f"  Resolved: {target} -> {ip}")
            except socket.gaierror:
                print(f"  [!] Could not resolve: {target}")
                results["lookups"].append({"target": target, "error": "Resolution failed"})
                continue

        geo = _ip_api_lookup(ip)

        if geo:
            print(f"  Country:  {geo.get('country', 'N/A')} ({geo.get('countryCode', 'N/A')})")
            print(f"  Region:   {geo.get('regionName', 'N/A')}, {geo.get('city', 'N/A')}")
            print(f"  ISP:      {geo.get('isp', 'N/A')}")
            print(f"  Org:      {geo.get('org', 'N/A')}")
            print(f"  ASN:      {geo.get('as', 'N/A')}")
            print(f"  Lat/Lon:  {geo.get('lat', 'N/A')}, {geo.get('lon', 'N/A')}")
            print(f"  Timezone: {geo.get('timezone', 'N/A')}")

            # Check for hosting/cloud providers in org name
            org = (geo.get("org", "") + " " + geo.get("isp", "")).upper()
            cloud = _detect_cloud_from_org(org)
            if cloud:
                print(f"  Cloud:    {cloud}")
                geo["cloud_provider"] = cloud
                if cloud not in results["cloud_providers_seen"]:
                    results["cloud_providers_seen"].append(cloud)

            # Collect unique ASNs and countries
            asn = geo.get("as", "")
            country = geo.get("country", "")
            if asn and asn not in results["asns_seen"]:
                results["asns_seen"].append(asn)
            if country and country not in results["countries_seen"]:
                results["countries_seen"].append(country)

            geo["target"] = target
            geo["resolved_ip"] = ip
            results["lookups"].append(geo)
        else:
            print(f"  [!] Lookup failed")
            results["lookups"].append({"target": target, "resolved_ip": ip, "error": "Lookup failed"})

    print("\n" + "=" * 60)
    print(f"[*] IP Geo complete")
    print(f"    Targets:     {total}")
    print(f"    Successful:  {sum(1 for l in results['lookups'] if 'error' not in l)}")
    print(f"    Countries:   {', '.join(results['countries_seen']) or 'N/A'}")
    if results["asns_seen"]:
        print(f"    ASNs seen:   {len(results['asns_seen'])}")
    if results["cloud_providers_seen"]:
        print(f"    Cloud:       {', '.join(results['cloud_providers_seen'])}")
    print("=" * 60)

    return results


# ---------------------------------------------------------------------------
# Geo Backends
# ---------------------------------------------------------------------------

def _ip_api_lookup(ip: str) -> Optional[Dict]:
    """Free geo lookup via ip-api.com (no key required, 45 req/min limit)."""
    try:
        from urllib.request import Request, urlopen
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode("utf-8"))
        if data.get("status") == "success":
            return data
        return None
    except Exception:
        return None


def _detect_cloud_from_org(org_upper: str) -> str:
    """Detect cloud provider from org/ISP name."""
    providers = {
        "AMAZON": "AWS",
        "AMAZONAWS": "AWS",
        "MICROSOFT": "Azure",
        "AZURE": "Azure",
        "GOOGLE": "GCP",
        "CLOUDFLARE": "Cloudflare",
        "FASTLY": "Fastly",
        "AKAMAI": "Akamai",
        "DIGITALOCEAN": "DigitalOcean",
        "LINODE": "Linode/Akamai",
        "VULTR": "Vultr",
        "HETZNER": "Hetzner",
        "OVH": "OVHcloud",
        "RACKSPACE": "Rackspace",
    }
    for keyword, provider in providers.items():
        if keyword in org_upper:
            return provider
    return ""


def _is_ip(s: str) -> bool:
    """Check if string looks like an IPv4/v6 address."""
    import re
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s) or ":" in s)


def _get_ipinfo_key() -> str:
    try:
        return get_api_key_manager().get_key("ipinfo") or ""
    except Exception:
        return ""


# Fix missing Optional import
from typing import Optional
