"""
Web Tech Fingerprinter - Pure Python web technology identification
Detects CMS, frameworks, JavaScript libraries, web servers, and more
Uses HTTP headers, HTML signatures, and common patterns (no external CLI required)
"""
import re
from typing import Dict, Any, Callable, List
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# Common technology signatures
TECH_SIGNATURES = {
    "WordPress": [
        r"wordpress",
        r"wp-content",
        r"wp-includes",
        r"wp-json",
        r"Wordpress",
    ],
    "Drupal": [
        r"drupal",
        r"/sites/all/modules",
        r"/sites/default",
        r"Drupal\.settings",
    ],
    "Joomla": [
        r"joomla",
        r"/media/",
        r"/components/",
        r"Joomla!",
    ],
    "Magento": [
        r"magento",
        r"/skin/",
        r"/media/",
        r"MAGENTO",
    ],
    "Shopify": [
        r"shopify",
        r"myshopify.com",
        r"cdn.shopify.com",
    ],
    "Wix": [
        r"wix.com",
        r"wixstatic",
    ],
    "Squarespace": [
        r"squarespace.com",
        r"-sqsp-",
    ],
    "Bootstrap": [
        r"bootstrap\.css",
        r"bootstrap\.js",
        r"bootstrap\.min",
    ],
    "jQuery": [
        r"jquery\.js",
        r"jquery\.min\.js",
        r"\$\.ajax",
        r"jQuery",
    ],
    "React": [
        r"react\.js",
        r"react\.production",
        r"__REACT",
        r"root\.render",
    ],
    "Vue.js": [
        r"vue\.js",
        r"vue\.min\.js",
        r"__VUE__",
    ],
    "Angular": [
        r"angular\.js",
        r"ng-app",
        r"ng-version",
    ],
    "TypeScript": [
        r"\.ts'",
        r"typescript",
    ],
    "Node.js": [
        r"nodejs",
        r"Express",
    ],
    "Apache": [
        r"Apache",
        r"Apache\/\d+",
    ],
    "Nginx": [
        r"nginx",
        r"Nginx\/\d+",
    ],
    "IIS": [
        r"Microsoft-IIS",
        r"X-Powered-By: ASP",
    ],
    "PHP": [
        r"X-Powered-By: PHP",
        r"\.php\?",
        r"php_uname",
    ],
    "Python": [
        r"X-Powered-By:.*Python",
        r"Werkzeug",
        r"Django",
    ],
    "Flask": [
        r"Flask",
        r"Werkzeug",
    ],
    "Django": [
        r"Django",
        r"/admin/",
    ],
    "ASP.NET": [
        r"ASP\.NET",
        r"X-AspNet",
        r"X-Powered-By:.*ASP",
    ],
    "Java": [
        r"JSession",
        r"jsessionid",
        r"X-Powered-By:.*Java",
    ],
    "Tomcat": [
        r"Tomcat",
        r"tomcat",
    ],
}


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Fingerprint web technologies using HTTP headers and HTML patterns.
    
    Params:
        target: Target URL (e.g., https://example.com)
        timeout: Request timeout in seconds (default: 10)
    """
    target = params.get("target", "").strip()
    timeout = int(params.get("timeout", 10))
    
    if not target:
        print("[ERROR] No target specified")
        return {"error": "No target specified"}
    
    # Add http:// if no protocol specified
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    results = {
        "target": target,
        "technologies": [],
        "headers": {},
        "status": None,
        "error": None,
    }
    
    print(f"[*] Web fingerprinting for: {target}")
    print("=" * 60)
    
    try:
        # Make request
        req = Request(target, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
        with urlopen(req, timeout=timeout) as response:
            status = response.status
            headers = dict(response.headers)
            html = response.read().decode('utf-8', errors='ignore')
            
            results["status"] = status
            results["headers"] = {k: v for k, v in headers.items() if k.lower() in [
                'server', 'x-powered-by', 'x-aspnet-version', 'x-runtime', 'x-backend',
                'via', 'content-type', 'set-cookie', 'cache-control'
            ]}
            
            print(f"[+] Status: {status}")
            if 'server' in headers:
                print(f"[+] Server: {headers['server']}")
            if 'x-powered-by' in headers:
                print(f"[+] Powered-by: {headers['x-powered-by']}")
            
            # Detect technologies
            techs = _detect_technologies(html, headers)
            results["technologies"] = techs
            
            if techs:
                print(f"\n[+] Detected technologies ({len(techs)}):")
                for tech in sorted(set(techs)):
                    print(f"    - {tech}")
            else:
                print("\n[-] No specific technologies detected")
    
    except HTTPError as e:
        results["error"] = f"HTTP {e.code}"
        print(f"[!] HTTP Error {e.code}")
    except URLError as e:
        results["error"] = str(e.reason)
        print(f"[!] Connection error: {e.reason}")
    except Exception as e:
        results["error"] = str(e)
        print(f"[!] Error: {e}")
    
    print("=" * 60)
    print("[*] Fingerprinting complete")
    
    return results


def _detect_technologies(html: str, headers: Dict[str, str]) -> List[str]:
    """Detect technologies from HTML and HTTP headers."""
    detected = []
    
    # Combine all text to search
    search_text = html + " ".join(f"{k}: {v}" for k, v in headers.items())
    search_text_lower = search_text.lower()
    
    # Check each technology's signatures
    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            try:
                if re.search(pattern, search_text_lower, re.IGNORECASE):
                    detected.append(tech)
                    break  # Found this tech, move to next tech
            except Exception:
                pass
    
    return detected
