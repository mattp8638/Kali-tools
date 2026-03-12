"""
Cloud Provider / IP Range Detection - Identify cloud infrastructure ownership.
Downloads and caches official IP range lists from AWS, Azure, GCP, Cloudflare, Fastly, etc.
Critical for scoping: a Cloudflare-proxied target changes your recon approach entirely.
"""
import ipaddress
import json
import os
import time
from typing import Dict, Any, Callable, List, Optional


# Cache dir and max age (24 hours)
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".kali_tools", "cloud_ranges")
CACHE_MAX_AGE = 86400  # 24 hours in seconds

# Official IP range sources
RANGE_SOURCES = {
    "AWS": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "GCP": "https://www.gstatic.com/ipranges/cloud.json",
    "Azure": "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20240115.json",
    "Cloudflare": "https://api.cloudflare.com/client/v4/ips",
    "Fastly": "https://api.fastly.com/public-ip-list",
    "Oracle": "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
}

# Fallback static ranges for offline/fallback use (well-known ranges, periodically updated)
STATIC_RANGES: Dict[str, List[str]] = {
    "Cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
        "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/16",
        "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
        "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
        "199.232.0.0/16",
    ],
    "GitHub": [
        "192.30.252.0/22", "185.199.108.0/22", "140.82.112.0/20",
    ],
    "DigitalOcean": [
        "104.131.0.0/18", "104.236.0.0/16", "138.197.0.0/16",
        "159.203.0.0/16", "167.99.0.0/16",
    ],
}


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Identify which cloud provider(s) own a set of IP addresses.

    Params:
        targets: Comma-separated IP addresses (e.g. 1.2.3.4, 10.0.0.1)
        providers: Providers to check (comma-separated: aws,gcp,azure,cloudflare,fastly)
                   or 'all' (default)
        refresh_cache: Force refresh of IP range lists (default: false)
    """
    raw_targets = params.get("targets", "").strip()
    providers_raw = params.get("providers", "all").strip().lower()
    refresh = str(params.get("refresh_cache", "false")).lower() in ("true", "1", "yes")

    if not raw_targets:
        print("[ERROR] At least one IP address is required")
        return {"error": "No targets provided"}

    targets = [t.strip() for t in raw_targets.replace("\n", ",").split(",") if t.strip()]

    if providers_raw == "all":
        selected = list(RANGE_SOURCES.keys())
    else:
        selected = [p.strip().upper() for p in providers_raw.split(",")]

    print(f"[*] Cloud Provider / IP Range Detection")
    print(f"[*] Targets:   {len(targets)} IP(s)")
    print(f"[*] Providers: {', '.join(selected)}")
    print("=" * 60)

    # Load IP ranges
    print("\n--- Loading IP Ranges ---")
    os.makedirs(CACHE_DIR, exist_ok=True)

    provider_ranges: Dict[str, List] = {}
    for provider in selected:
        if is_cancelled and is_cancelled():
            break
        ranges = _load_ranges(provider, refresh)
        provider_ranges[provider] = ranges
        print(f"  {provider}: {len(ranges)} range(s) loaded")

    results: Dict[str, Any] = {
        "targets": targets,
        "results": [],
        "cloud_distribution": {},
        "non_cloud": [],
    }

    total = len(targets)
    print("\n--- Checking IPs ---")

    for i, target in enumerate(targets):
        if is_cancelled and is_cancelled():
            break
        if on_progress:
            on_progress(i + 1, total)

        print(f"\n  [{i+1}/{total}] {target}")

        try:
            ip_obj = ipaddress.ip_address(target)
        except ValueError:
            print(f"    [!] Invalid IP address: {target}")
            results["results"].append({"ip": target, "error": "Invalid IP", "provider": None})
            continue

        matched_providers = []
        matched_services = []

        for provider, ranges in provider_ranges.items():
            for net_str, service in ranges:
                try:
                    if ip_obj in ipaddress.ip_network(net_str, strict=False):
                        matched_providers.append(provider)
                        matched_services.append(service or provider)
                        break
                except ValueError:
                    continue

        # Also check static ranges as fallback
        for provider, static_nets in STATIC_RANGES.items():
            if provider not in matched_providers:
                for net_str in static_nets:
                    try:
                        if ip_obj in ipaddress.ip_network(net_str, strict=False):
                            matched_providers.append(provider)
                            matched_services.append(provider)
                            break
                    except ValueError:
                        continue

        entry = {
            "ip": target,
            "provider": ", ".join(set(matched_providers)) if matched_providers else "Unknown",
            "services": list(set(matched_services)),
            "is_cloud": bool(matched_providers),
        }
        results["results"].append(entry)

        if matched_providers:
            unique_providers = list(set(matched_providers))
            print(f"    [+] Provider: {', '.join(unique_providers)}")
            if matched_services:
                unique_services = [s for s in set(matched_services) if s and s not in unique_providers]
                if unique_services:
                    print(f"        Service:  {', '.join(unique_services)}")
            for p in unique_providers:
                results["cloud_distribution"][p] = results["cloud_distribution"].get(p, 0) + 1
        else:
            print(f"    [-] Not in known cloud ranges (dedicated/on-prem)")
            results["non_cloud"].append(target)

    print("\n" + "=" * 60)
    print(f"[*] Cloud detection complete")
    cloud_count = sum(1 for r in results["results"] if r.get("is_cloud"))
    print(f"    Cloud IPs:   {cloud_count}/{total}")
    print(f"    Non-cloud:   {len(results['non_cloud'])}/{total}")
    if results["cloud_distribution"]:
        print(f"    Distribution:")
        for provider, count in sorted(results["cloud_distribution"].items(), key=lambda x: -x[1]):
            print(f"      {provider}: {count}")
    print("=" * 60)

    return results


# ---------------------------------------------------------------------------
# IP Range Loading
# ---------------------------------------------------------------------------

def _load_ranges(provider: str, refresh: bool = False) -> List[tuple]:
    """Load IP ranges for a provider, using cache where possible."""
    cache_file = os.path.join(CACHE_DIR, f"{provider.lower()}.json")

    # Check cache
    if not refresh and os.path.exists(cache_file):
        age = time.time() - os.path.getmtime(cache_file)
        if age < CACHE_MAX_AGE:
            try:
                with open(cache_file) as f:
                    return json.load(f)
            except Exception:
                pass

    # Download fresh
    ranges = _fetch_ranges(provider)

    if ranges:
        try:
            with open(cache_file, "w") as f:
                json.dump(ranges, f)
        except Exception:
            pass

    return ranges


def _fetch_ranges(provider: str) -> List[tuple]:
    """Download and parse IP ranges for a provider. Returns list of (network, service) tuples."""
    from urllib.request import Request, urlopen
    import ssl

    url = RANGE_SOURCES.get(provider)
    if not url:
        return []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=15, context=ctx) as resp:
            raw = resp.read().decode("utf-8")
    except Exception:
        return []

    ranges = []

    try:
        if provider == "AWS":
            data = json.loads(raw)
            for prefix in data.get("prefixes", []):
                ranges.append((prefix["ip_prefix"], prefix.get("service", "AWS")))
            for prefix in data.get("ipv6_prefixes", []):
                ranges.append((prefix["ipv6_prefix"], prefix.get("service", "AWS")))

        elif provider == "GCP":
            data = json.loads(raw)
            for prefix_entry in data.get("prefixes", []):
                net = prefix_entry.get("ipv4Prefix") or prefix_entry.get("ipv6Prefix")
                if net:
                    ranges.append((net, "GCP"))

        elif provider == "Azure":
            data = json.loads(raw)
            for value in data.get("values", []):
                svc_name = value.get("name", "Azure")
                for prefix in value.get("properties", {}).get("addressPrefixes", []):
                    ranges.append((prefix, svc_name))

        elif provider == "Cloudflare":
            data = json.loads(raw)
            for prefix in data.get("result", {}).get("ipv4_cidrs", []):
                ranges.append((prefix, "Cloudflare"))
            for prefix in data.get("result", {}).get("ipv6_cidrs", []):
                ranges.append((prefix, "Cloudflare"))

        elif provider == "Fastly":
            data = json.loads(raw)
            for prefix in data.get("addresses", []):
                ranges.append((prefix, "Fastly"))
            for prefix in data.get("ipv6_addresses", []):
                ranges.append((prefix, "Fastly"))

        elif provider == "Oracle":
            data = json.loads(raw)
            for region in data.get("regions", []):
                for cidr_entry in region.get("cidrs", []):
                    ranges.append((cidr_entry["cidr"], f"Oracle/{region['region']}"))

    except Exception:
        pass

    return ranges
