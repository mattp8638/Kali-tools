"""
Search Dorks - Automated Google/Bing dorking for passive recon.
Uses Bing scraping (more TOS-friendly than Google) and optional Google Custom Search API.
Generates structured dork queries for common recon patterns.
"""
import json
import re
import time
import urllib.parse
from typing import Dict, Any, Callable, List, Optional
from kali_host.core.api_keys import get_api_key_manager


# Built-in dork templates by category
DORK_TEMPLATES = {
    "files": [
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:doc OR filetype:docx',
        'site:{domain} filetype:xls OR filetype:xlsx',
        'site:{domain} filetype:txt',
        'site:{domain} filetype:xml',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:log',
        'site:{domain} filetype:env',
        'site:{domain} filetype:bak',
    ],
    "admin": [
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login',
        'site:{domain} inurl:dashboard',
        'site:{domain} inurl:portal',
        'site:{domain} inurl:wp-admin',
        'site:{domain} inurl:phpmyadmin',
        'site:{domain} inurl:cpanel',
        'site:{domain} inurl:webmail',
    ],
    "sensitive": [
        'site:{domain} intitle:"index of"',
        'site:{domain} inurl:config',
        'site:{domain} inurl:backup',
        'site:{domain} inurl:.git',
        'site:{domain} inurl:/.env',
        'site:{domain} "password" filetype:txt',
        'site:{domain} "api_key" OR "apikey" OR "api key"',
        'site:{domain} "secret" OR "token"',
    ],
    "subdomains": [
        'site:*.{domain}',
        'site:*.{domain} -www',
    ],
    "tech": [
        'site:{domain} "Powered by"',
        'site:{domain} "Built with"',
        'site:{domain} inurl:wp-content',
        'site:{domain} inurl:wp-includes',
        'site:{domain} "joomla"',
        'site:{domain} inurl:/drupal/',
    ],
    "emails": [
        'site:{domain} "@{domain}"',
        'site:{domain} "email" OR "contact"',
        '"{domain}" email',
    ],
    "cache": [
        'cache:{domain}',
        'related:{domain}',
        'link:{domain}',
    ],
}


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Automated dork query generation and Bing search.

    Params:
        domain: Target domain to dork
        categories: Comma-separated categories (files,admin,sensitive,subdomains,tech,emails,cache)
                    or 'all' for everything
        use_bing: Scrape Bing for results (default: true)
        google_api_key: Google Custom Search API key (optional)
        google_cse_id: Google Custom Search Engine ID (optional)
        max_results_per_dork: Max results per query (default: 5)
        delay: Delay between requests in seconds (default: 2)
    """
    domain = params.get("domain", "").strip().lower()
    if domain.startswith("http"):
        domain = re.sub(r'https?://', '', domain).split('/')[0]

    categories_raw = params.get("categories", "all").strip().lower()
    use_bing = str(params.get("use_bing", "true")).lower() not in ("false", "0", "no")
    google_key = params.get("google_api_key", "").strip() or _get_key("google_api_key")
    google_cse = params.get("google_cse_id", "").strip() or _get_key("google_cse_id")
    max_results = int(params.get("max_results_per_dork", 5))
    delay = float(params.get("delay", 2))

    if not domain:
        print("[ERROR] A domain is required (e.g. example.com)")
        return {"error": "No domain provided"}

    if categories_raw == "all":
        selected_categories = list(DORK_TEMPLATES.keys())
    else:
        selected_categories = [c.strip() for c in categories_raw.split(",") if c.strip() in DORK_TEMPLATES]
        if not selected_categories:
            selected_categories = list(DORK_TEMPLATES.keys())

    # Build dork list
    dorks = []
    for cat in selected_categories:
        for template in DORK_TEMPLATES[cat]:
            dorks.append({"query": template.replace("{domain}", domain), "category": cat})

    print(f"[*] Search Dorks starting for: {domain}")
    print(f"[*] Categories: {', '.join(selected_categories)}")
    print(f"[*] Generated {len(dorks)} dork queries")
    print("=" * 60)

    results: Dict[str, Any] = {
        "domain": domain,
        "dorks_generated": [d["query"] for d in dorks],
        "dorks_by_category": {cat: [] for cat in selected_categories},
        "search_results": [],
        "interesting_findings": [],
    }

    total = len(dorks)

    # Always output the dork list for manual use
    print("\n--- Generated Dork Queries ---")
    for cat in selected_categories:
        cat_dorks = [d["query"] for d in dorks if d["category"] == cat]
        print(f"\n  [{cat.upper()}]")
        for q in cat_dorks:
            print(f"    {q}")
            results["dorks_by_category"][cat].append(q)

    # Bing scraping
    if use_bing:
        print(f"\n--- Bing Search Results ---")
        print(f"  [*] Searching Bing (delay: {delay}s between requests)...")

        for i, dork in enumerate(dorks):
            if is_cancelled and is_cancelled():
                break

            if on_progress:
                on_progress(i + 1, total)

            query = dork["query"]
            cat = dork["category"]

            try:
                hits = _bing_search(query, max_results)
                if hits:
                    print(f"\n  [+] '{query}'")
                    for hit in hits:
                        print(f"      -> {hit['title']}")
                        print(f"         {hit['url']}")
                        results["search_results"].append({
                            "query": query,
                            "category": cat,
                            "title": hit["title"],
                            "url": hit["url"],
                        })
                        # Flag anything that looks interesting
                        url_lower = hit["url"].lower()
                        if any(x in url_lower for x in [".env", ".sql", ".bak", "backup", "config", "admin", "login", ".git"]):
                            results["interesting_findings"].append(hit["url"])

                    time.sleep(delay)
            except Exception as e:
                print(f"  [!] Bing search error: {e}")

    # Google Custom Search
    elif google_key and google_cse:
        print(f"\n--- Google Custom Search Results ---")
        for i, dork in enumerate(dorks):
            if is_cancelled and is_cancelled():
                break

            if on_progress:
                on_progress(i + 1, total)

            query = dork["query"]
            cat = dork["category"]

            try:
                hits = _google_cse_search(query, google_key, google_cse, max_results)
                if hits:
                    print(f"\n  [+] '{query}'")
                    for hit in hits:
                        print(f"      -> {hit['title']}")
                        print(f"         {hit['url']}")
                        results["search_results"].append({
                            "query": query,
                            "category": cat,
                            "title": hit["title"],
                            "url": hit["url"],
                        })

                time.sleep(delay)
            except Exception as e:
                print(f"  [!] Google CSE error: {e}")

    print("\n" + "=" * 60)
    print(f"[*] Dorking complete for: {domain}")
    print(f"    Dorks generated:   {len(dorks)}")
    print(f"    Search results:    {len(results['search_results'])}")
    if results["interesting_findings"]:
        print(f"\n  [!] Interesting findings ({len(results['interesting_findings'])}):")
        for f in results["interesting_findings"]:
            print(f"      -> {f}")
    print("=" * 60)

    return results


# ---------------------------------------------------------------------------
# Search Backends
# ---------------------------------------------------------------------------

def _bing_search(query: str, max_results: int = 5) -> List[Dict]:
    """Scrape Bing search results for a query."""
    from urllib.request import Request, urlopen

    encoded = urllib.parse.quote_plus(query)
    url = f"https://www.bing.com/search?q={encoded}&count={max_results * 2}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml",
    }

    req = Request(url, headers=headers)
    results = []

    with urlopen(req, timeout=10) as response:
        html = response.read().decode("utf-8", errors="ignore")

    # Extract result titles + URLs from Bing HTML
    # Bing result pattern: <h2><a href="URL">Title</a></h2>
    pattern = r'<h2[^>]*><a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a></h2>'
    matches = re.findall(pattern, html, re.DOTALL)

    for url_raw, title_raw in matches[:max_results]:
        title = re.sub(r'<[^>]+>', '', title_raw).strip()
        # Skip Bing's own URLs
        if "bing.com" in url_raw or "microsoft.com" in url_raw:
            continue
        results.append({"url": url_raw, "title": title or url_raw})

    return results


def _google_cse_search(query: str, api_key: str, cse_id: str, max_results: int = 5) -> List[Dict]:
    """Search via Google Custom Search API."""
    from urllib.request import Request, urlopen

    params = {
        "key": api_key,
        "cx": cse_id,
        "q": query,
        "num": min(max_results, 10),
    }
    url = "https://www.googleapis.com/customsearch/v1?" + urllib.parse.urlencode(params)
    req = Request(url)
    results = []

    with urlopen(req, timeout=10) as response:
        data = json.loads(response.read().decode("utf-8"))

    for item in data.get("items", []):
        results.append({"url": item.get("link", ""), "title": item.get("title", "")})

    return results


# ---------------------------------------------------------------------------
# API Key Helper
# ---------------------------------------------------------------------------

def _get_key(name: str) -> str:
    try:
        return get_api_key_manager().get_key(name) or ""
    except Exception:
        return ""
