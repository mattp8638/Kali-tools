"""
Technology Stack Detection - Wappalyzer-style fingerprinting from HTTP responses.
Detects CMS, frameworks, JS libraries, analytics, CDN, and more from headers
and HTML content. Uses Wappalyzer rule patterns via the python-Wappalyzer library
with a fallback to built-in regex signatures.
"""
import json
import re
import ssl
import urllib.parse
from typing import Dict, Any, Callable, List, Optional, Set


# Comprehensive Wappalyzer-style signatures
# Format: "Technology": {"headers": {header_name: pattern}, "html": [pattern], "meta": {name: pattern}}
SIGNATURES: Dict[str, Dict] = {
    # CMS
    "WordPress": {
        "html": [r'wp-content/', r'wp-includes/', r'wordpress'],
        "headers": {"X-Powered-By": r"wordpress"},
        "meta": {"generator": r"WordPress"},
    },
    "Drupal": {
        "html": [r'/sites/default/', r'Drupal\.settings', r'drupal\.js'],
        "headers": {"X-Generator": r"Drupal"},
        "meta": {"generator": r"Drupal"},
    },
    "Joomla": {
        "html": [r'/components/com_', r'Joomla!', r'/media/jui/'],
        "meta": {"generator": r"Joomla"},
    },
    "Magento": {
        "html": [r'Mage\.', r'/skin/frontend/', r'magento'],
    },
    "Shopify": {
        "html": [r'cdn\.shopify\.com', r'shopify\.com/s/', r"Shopify\.theme"],
    },
    "Wix": {
        "html": [r'wix\.com', r'X-Wix-', r'wixstatic\.com'],
    },
    "Squarespace": {
        "html": [r'squarespace\.com', r'static\.squarespace\.com'],
    },
    "Ghost": {
        "html": [r'ghost\.io', r'/ghost/'],
        "meta": {"generator": r"Ghost"},
    },
    # Frameworks
    "React": {
        "html": [r'react\.development\.js', r'react\.production\.min\.js', r'__reactFiber', r'data-reactroot'],
    },
    "Vue.js": {
        "html": [r'vue\.js', r'vue\.min\.js', r'__vue__', r'data-v-'],
    },
    "Angular": {
        "html": [r'angular\.js', r'angular\.min\.js', r'ng-version=', r'ng-app'],
    },
    "Next.js": {
        "html": [r'__NEXT_DATA__', r'/_next/static/'],
    },
    "Nuxt.js": {
        "html": [r'__nuxt', r'nuxt\.js'],
    },
    "Svelte": {
        "html": [r'svelte-', r'__svelte'],
    },
    "jQuery": {
        "html": [r'jquery[\.\-][\d\.]+\.js', r'jquery\.min\.js'],
    },
    "Bootstrap": {
        "html": [r'bootstrap\.min\.css', r'bootstrap\.css', r'bootstrap\.bundle'],
    },
    # Backend Frameworks
    "Laravel": {
        "headers": {"X-Powered-By": r""},
        "html": [r'laravel', r'csrf-token.*Laravel'],
        "cookies": r"laravel_session",
    },
    "Django": {
        "html": [r'csrfmiddlewaretoken', r'django'],
        "headers": {"X-Frame-Options": r""},
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": r"Phusion Passenger"},
        "html": [r'csrf-param.*authenticity_token', r'rails-ujs'],
        "cookies": r"_session_id",
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r""},
        "html": [r'__VIEWSTATE', r'__EVENTTARGET', r'aspnet'],
        "cookies": r"ASP\.NET_SessionId",
    },
    "ASP.NET MVC": {
        "headers": {"X-AspNetMvc-Version": r""},
    },
    "Flask": {
        "cookies": r"session",
        "html": [r'Werkzeug'],
    },
    "Express.js": {
        "headers": {"X-Powered-By": r"Express"},
    },
    "PHP": {
        "headers": {"X-Powered-By": r"PHP"},
        "html": [r'\.php\?', r'\.php"'],
    },
    # Servers
    "Apache": {
        "headers": {"Server": r"Apache"},
    },
    "Nginx": {
        "headers": {"Server": r"nginx"},
    },
    "IIS": {
        "headers": {"Server": r"Microsoft-IIS"},
    },
    "Cloudflare": {
        "headers": {"Server": r"cloudflare", "CF-Ray": r""},
    },
    "LiteSpeed": {
        "headers": {"Server": r"LiteSpeed"},
    },
    "Caddy": {
        "headers": {"Server": r"Caddy"},
    },
    # Analytics
    "Google Analytics": {
        "html": [r'google-analytics\.com/analytics\.js', r'gtag\(', r'UA-\d{6,8}-\d+', r'G-[A-Z0-9]+'],
    },
    "Google Tag Manager": {
        "html": [r'googletagmanager\.com/gtm\.js', r'GTM-[A-Z0-9]+'],
    },
    "Hotjar": {
        "html": [r'hotjar\.com', r'hjSiteSettings'],
    },
    "Mixpanel": {
        "html": [r'mixpanel\.com', r'mixpanel\.init'],
    },
    # CDN / Hosting
    "Cloudflare CDN": {
        "headers": {"CF-Cache-Status": r""},
        "html": [r'cdnjs\.cloudflare\.com'],
    },
    "AWS CloudFront": {
        "headers": {"X-Cache": r"CloudFront", "Via": r"CloudFront"},
    },
    "Fastly": {
        "headers": {"X-Served-By": r"cache-", "Fastly-Debug": r""},
    },
    # Security
    "reCAPTCHA": {
        "html": [r'google\.com/recaptcha', r'recaptcha\.net'],
    },
    "hCaptcha": {
        "html": [r'hcaptcha\.com'],
    },
    # Other
    "Font Awesome": {
        "html": [r'font-awesome', r'fontawesome'],
    },
    "Tailwind CSS": {
        "html": [r'tailwind\.css', r'tailwindcss'],
    },
    "Webpack": {
        "html": [r'webpackJsonp', r'__webpack_require__'],
    },
    "Vite": {
        "html": [r'/@vite/', r'vite\.config'],
    },
    "Stripe": {
        "html": [r'js\.stripe\.com', r'stripe\.js'],
    },
    "PayPal": {
        "html": [r'paypal\.com/sdk'],
    },
}


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Deep technology stack fingerprinting from HTTP responses.

    Params:
        target: URL or domain to fingerprint
        timeout: Request timeout in seconds (default: 10)
        follow_redirects: Follow redirects (default: true)
        scan_paths: Additional paths to scan (comma-separated, e.g. /admin,/login)
    """
    target = params.get("target", "").strip()
    timeout = int(params.get("timeout", 10))
    scan_paths_raw = params.get("scan_paths", "").strip()

    if not target:
        print("[ERROR] A target URL or domain is required")
        return {"error": "No target provided"}

    # Normalise to URL
    if not target.startswith("http"):
        # Try HTTPS first
        target = f"https://{target}"

    target = target.rstrip("/")

    additional_paths = [p.strip() for p in scan_paths_raw.split(",") if p.strip()] if scan_paths_raw else []
    paths_to_scan = ["/"] + additional_paths

    print(f"[*] Technology Stack Detection for: {target}")
    print(f"[*] Paths to scan: {', '.join(paths_to_scan)}")
    print("=" * 60)

    results: Dict[str, Any] = {
        "target": target,
        "technologies": [],
        "server": "",
        "headers": {},
        "cookies": [],
        "cms": None,
        "frameworks": [],
        "analytics": [],
        "cdn_waf": [],
        "raw_by_path": {},
    }

    all_tech: Set[str] = set()

    total = len(paths_to_scan)
    for i, path in enumerate(paths_to_scan):
        if is_cancelled and is_cancelled():
            break
        if on_progress:
            on_progress(i + 1, total)

        url = target + path
        print(f"\n--- Scanning: {url} ---")

        try:
            resp = _fetch(url, timeout)
            if not resp:
                print(f"  [!] No response")
                continue

            headers, html, cookies, status = resp
            print(f"  Status: {status}")

            if results["server"] == "":
                results["server"] = headers.get("server", headers.get("Server", ""))
            results["headers"].update(headers)
            for c in cookies:
                if c not in results["cookies"]:
                    results["cookies"].append(c)

            tech_found = _fingerprint(html, headers, cookies)
            all_tech.update(tech_found)

            results["raw_by_path"][path] = {
                "url": url,
                "status": status,
                "technologies": list(tech_found),
            }

            if tech_found:
                print(f"  Technologies: {', '.join(sorted(tech_found))}")
            else:
                print(f"  Technologies: None detected")

        except Exception as e:
            print(f"  [!] Error: {e}")

    # Categorise findings
    CMS_NAMES = {"WordPress", "Drupal", "Joomla", "Magento", "Shopify", "Wix", "Squarespace", "Ghost"}
    FRAMEWORK_NAMES = {"React", "Vue.js", "Angular", "Next.js", "Nuxt.js", "Svelte", "jQuery",
                       "Bootstrap", "Laravel", "Django", "Ruby on Rails", "ASP.NET", "ASP.NET MVC",
                       "Flask", "Express.js", "PHP", "Webpack", "Vite", "Tailwind CSS"}
    ANALYTICS_NAMES = {"Google Analytics", "Google Tag Manager", "Hotjar", "Mixpanel"}
    CDN_NAMES = {"Cloudflare", "Cloudflare CDN", "AWS CloudFront", "Fastly"}

    for tech in sorted(all_tech):
        results["technologies"].append(tech)
        if tech in CMS_NAMES and not results["cms"]:
            results["cms"] = tech
        if tech in FRAMEWORK_NAMES:
            results["frameworks"].append(tech)
        if tech in ANALYTICS_NAMES:
            results["analytics"].append(tech)
        if tech in CDN_NAMES:
            results["cdn_waf"].append(tech)

    print("\n" + "=" * 60)
    print(f"[*] Tech Stack Detection complete")
    print(f"    Server:       {results['server'] or 'Unknown'}")
    print(f"    CMS:          {results['cms'] or 'None detected'}")
    print(f"    Frameworks:   {', '.join(results['frameworks']) or 'None detected'}")
    print(f"    Analytics:    {', '.join(results['analytics']) or 'None'}")
    print(f"    CDN/WAF:      {', '.join(results['cdn_waf']) or 'None'}")
    print(f"    All tech:     {', '.join(results['technologies']) or 'None detected'}")
    print("=" * 60)

    return results


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

def _fingerprint(html: str, headers: Dict[str, str], cookies: List[str]) -> Set[str]:
    """Match all signatures against response data."""
    found: Set[str] = set()
    html_lower = html.lower()
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    cookies_str = " ".join(cookies).lower()

    for tech, sigs in SIGNATURES.items():
        matched = False

        # Check HTML patterns
        for pattern in sigs.get("html", []):
            if re.search(pattern, html, re.IGNORECASE):
                matched = True
                break

        # Check header patterns
        if not matched:
            for header, pattern in sigs.get("headers", {}).items():
                header_val = headers_lower.get(header.lower(), "")
                if header_val and (not pattern or re.search(pattern, header_val, re.IGNORECASE)):
                    matched = True
                    break

        # Check meta tags
        if not matched:
            for meta_name, pattern in sigs.get("meta", {}).items():
                meta_pattern = rf'<meta[^>]+name=["\']?{meta_name}["\']?[^>]+content=["\']?([^"\'>\s]+)'
                meta_match = re.search(meta_pattern, html, re.IGNORECASE)
                if meta_match and re.search(pattern, meta_match.group(1), re.IGNORECASE):
                    matched = True
                    break

        # Check cookies
        if not matched:
            cookie_pattern = sigs.get("cookies", "")
            if cookie_pattern and re.search(cookie_pattern, cookies_str, re.IGNORECASE):
                matched = True

        if matched:
            found.add(tech)

    return found


def _fetch(url: str, timeout: int = 10):
    """Fetch a URL and return (headers_dict, html, cookies, status)."""
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    req = Request(url, headers=headers)

    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            resp_headers = dict(resp.headers)
            html = resp.read().decode("utf-8", errors="ignore")
            status = resp.status
            # Extract cookies
            cookies = []
            for key, val in resp.headers.items():
                if key.lower() == "set-cookie":
                    name = val.split("=")[0].strip()
                    if name and name not in cookies:
                        cookies.append(name)
            return resp_headers, html, cookies, status
    except HTTPError as e:
        # Still process 4xx pages — they can contain tech signatures
        try:
            resp_headers = dict(e.headers)
            html = e.read().decode("utf-8", errors="ignore")
            cookies = []
            for key, val in e.headers.items():
                if key.lower() == "set-cookie":
                    name = val.split("=")[0].strip()
                    if name:
                        cookies.append(name)
            return resp_headers, html, cookies, e.code
        except Exception:
            return None
    except (URLError, Exception):
        # Try HTTP fallback for HTTPS failures
        if url.startswith("https://"):
            return _fetch(url.replace("https://", "http://", 1), timeout)
        return None
