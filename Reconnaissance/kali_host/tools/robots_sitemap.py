"""
Robots.txt & Sitemap Parser - Passive web content discovery.
Fetches robots.txt, sitemap.xml, sitemap_index.xml and extracts disallowed paths,
sitemaps, and all listed URLs. Disallowed paths are often the most interesting.
"""
import re
import urllib.parse
import ssl
from typing import Dict, Any, Callable, List, Optional


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Passive web content discovery via robots.txt and sitemaps.

    Params:
        target: URL or domain to inspect
        fetch_sitemaps: Download and parse sitemap URLs (default: true)
        max_sitemap_urls: Maximum sitemap URLs to retrieve (default: 200)
        timeout: Request timeout in seconds (default: 10)
    """
    target = params.get("target", "").strip()
    fetch_sitemaps = str(params.get("fetch_sitemaps", "true")).lower() not in ("false", "0", "no")
    max_sitemap_urls = int(params.get("max_sitemap_urls", 200))
    timeout = int(params.get("timeout", 10))

    if not target:
        print("[ERROR] A target URL or domain is required")
        return {"error": "No target provided"}

    # Normalise
    if not target.startswith("http"):
        target = f"https://{target}"
    target = target.rstrip("/")

    # Extract base
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    print(f"[*] Robots.txt / Sitemap Parser for: {base}")
    print("=" * 60)

    results: Dict[str, Any] = {
        "target": base,
        "robots_txt": {
            "found": False,
            "raw": "",
            "user_agents": [],
            "disallowed": [],
            "allowed": [],
            "sitemaps_listed": [],
            "crawl_delay": None,
        },
        "sitemaps": [],
        "sitemap_urls": [],
        "interesting_paths": [],
    }

    total_steps = 2
    step = 0

    def _prog():
        nonlocal step
        step += 1
        if on_progress:
            on_progress(step, total_steps)

    # ------------------------------------------------------------------
    # 1. Fetch robots.txt
    # ------------------------------------------------------------------
    print("\n--- robots.txt ---")
    robots_url = f"{base}/robots.txt"
    robots_raw = _fetch_text(robots_url, timeout)

    if robots_raw:
        results["robots_txt"]["found"] = True
        results["robots_txt"]["raw"] = robots_raw
        print(f"  [+] Found robots.txt ({len(robots_raw)} bytes)")

        parsed_robots = _parse_robots(robots_raw, base)
        results["robots_txt"].update(parsed_robots)

        if parsed_robots["disallowed"]:
            print(f"\n  [!] Disallowed paths ({len(parsed_robots['disallowed'])}):")
            for path in parsed_robots["disallowed"]:
                print(f"      {path}")
                if _is_interesting(path):
                    full_url = base + (path if path.startswith("/") else "/" + path)
                    if full_url not in results["interesting_paths"]:
                        results["interesting_paths"].append(full_url)

        if parsed_robots["allowed"]:
            print(f"\n  [+] Explicitly allowed paths ({len(parsed_robots['allowed'])}):")
            for path in parsed_robots["allowed"][:10]:
                print(f"      {path}")

        if parsed_robots["sitemaps_listed"]:
            print(f"\n  [+] Sitemaps listed: {len(parsed_robots['sitemaps_listed'])}")
            for s in parsed_robots["sitemaps_listed"]:
                print(f"      {s}")

        if parsed_robots["crawl_delay"]:
            print(f"\n  [+] Crawl-delay: {parsed_robots['crawl_delay']}")

        if parsed_robots["user_agents"]:
            unique_agents = list(set(parsed_robots["user_agents"]))
            print(f"\n  [+] User-agent rules: {len(unique_agents)} agent(s)")
    else:
        print(f"  [-] robots.txt not found or inaccessible")

    _prog()

    # ------------------------------------------------------------------
    # 2. Fetch and parse sitemaps
    # ------------------------------------------------------------------
    if fetch_sitemaps and not (is_cancelled and is_cancelled()):
        print("\n--- Sitemaps ---")

        # Collect all sitemap URLs to try
        sitemap_candidates = list(results["robots_txt"]["sitemaps_listed"])

        # Add common sitemap locations
        common_sitemaps = [
            f"{base}/sitemap.xml",
            f"{base}/sitemap_index.xml",
            f"{base}/sitemap-index.xml",
            f"{base}/sitemap1.xml",
            f"{base}/news-sitemap.xml",
            f"{base}/page-sitemap.xml",
            f"{base}/post-sitemap.xml",
        ]
        for url in common_sitemaps:
            if url not in sitemap_candidates:
                sitemap_candidates.append(url)

        all_sitemap_urls = []
        sitemaps_processed = []
        queue = list(sitemap_candidates)
        visited = set()

        while queue and len(all_sitemap_urls) < max_sitemap_urls:
            if is_cancelled and is_cancelled():
                break

            sm_url = queue.pop(0)
            if sm_url in visited:
                continue
            visited.add(sm_url)

            content = _fetch_text(sm_url, timeout)
            if not content:
                continue

            print(f"  [+] {sm_url}")
            sitemaps_processed.append(sm_url)

            # Check if it's a sitemap index (contains <sitemap> tags)
            child_sitemaps = re.findall(r'<loc>\s*(https?://[^<]+sitemap[^<]*\.xml[^<]*)\s*</loc>', content, re.IGNORECASE)
            for child in child_sitemaps:
                child = child.strip()
                if child not in visited:
                    queue.append(child)
                    print(f"      -> Child sitemap: {child}")

            # Extract all <loc> URLs (page URLs)
            page_urls = re.findall(r'<loc>\s*(https?://[^\s<]+)\s*</loc>', content, re.IGNORECASE)
            page_urls = [u.strip() for u in page_urls if "sitemap" not in u.lower()]

            for url in page_urls:
                if url not in all_sitemap_urls:
                    all_sitemap_urls.append(url)
                    if len(all_sitemap_urls) >= max_sitemap_urls:
                        break

        results["sitemaps"] = sitemaps_processed
        results["sitemap_urls"] = all_sitemap_urls

        if all_sitemap_urls:
            print(f"\n  [+] Found {len(all_sitemap_urls)} URL(s) across {len(sitemaps_processed)} sitemap(s)")
            for url in all_sitemap_urls[:20]:
                print(f"      {url}")
            if len(all_sitemap_urls) > 20:
                print(f"      ... and {len(all_sitemap_urls) - 20} more")
        else:
            print(f"  [-] No sitemap URLs found")

    _prog()

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"[*] robots.txt/Sitemap parsing complete")
    print(f"    robots.txt:       {'Found' if results['robots_txt']['found'] else 'Not found'}")
    print(f"    Disallowed paths: {len(results['robots_txt']['disallowed'])}")
    print(f"    Sitemaps found:   {len(results['sitemaps'])}")
    print(f"    Sitemap URLs:     {len(results['sitemap_urls'])}")
    if results["interesting_paths"]:
        print(f"\n  [!] Interesting disallowed paths:")
        for p in results["interesting_paths"]:
            print(f"      {p}")
    print("=" * 60)

    return results


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse_robots(content: str, base_url: str) -> Dict:
    """Parse robots.txt content into structured data."""
    result = {
        "user_agents": [],
        "disallowed": [],
        "allowed": [],
        "sitemaps_listed": [],
        "crawl_delay": None,
    }

    current_agents = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        lower = line.lower()

        if lower.startswith("user-agent:"):
            agent = line.split(":", 1)[1].strip()
            current_agents.append(agent)
            result["user_agents"].append(agent)

        elif lower.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path not in result["disallowed"]:
                result["disallowed"].append(path)

        elif lower.startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path and path not in result["allowed"]:
                result["allowed"].append(path)

        elif lower.startswith("sitemap:"):
            sitemap_url = line.split(":", 1)[1].strip()
            # Rejoin the URL (it may contain https: which got split)
            if "sitemap:" in lower:
                raw_val = line[len("sitemap:"):].strip()
                if raw_val and raw_val not in result["sitemaps_listed"]:
                    result["sitemaps_listed"].append(raw_val)

        elif lower.startswith("crawl-delay:"):
            try:
                result["crawl_delay"] = float(line.split(":", 1)[1].strip())
            except ValueError:
                pass

    # Fix sitemaps: re-collect using a simple regex instead
    result["sitemaps_listed"] = re.findall(r'(?i)^[Ss]itemap:\s*(https?://\S+)', content, re.MULTILINE)

    return result


def _is_interesting(path: str) -> bool:
    """Flag paths that are commonly sensitive."""
    interesting_keywords = [
        "admin", "login", "api", "config", "backup", "private",
        "secret", "internal", "staging", "dev", "debug", "upload",
        "webhook", ".env", ".git", ".htaccess", "cgi-bin", "phpmyadmin",
        "wp-admin", "dashboard", "console", "manage", "panel",
    ]
    path_lower = path.lower()
    return any(k in path_lower for k in interesting_keywords)


def _fetch_text(url: str, timeout: int = 10) -> Optional[str]:
    """Fetch text content from a URL."""
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {"User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"}

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status == 200:
                return resp.read().decode("utf-8", errors="ignore")
        return None
    except HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            location = e.headers.get("Location", "")
            if location and location != url:
                return _fetch_text(location, timeout)
        return None
    except (URLError, Exception):
        # Try HTTP fallback
        if url.startswith("https://"):
            return _fetch_text(url.replace("https://", "http://", 1), timeout)
        return None
