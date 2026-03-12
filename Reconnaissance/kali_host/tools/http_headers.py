"""
HTTP Header Analysis - Grab and analyse HTTP response headers.
Checks for security headers, server info, and technology fingerprinting.
"""
import socket
import ssl
from urllib.parse import urlparse
from typing import Dict, Any, Callable, List


SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "severity": "HIGH",
        "description": "Enforces HTTPS connections",
    },
    "content-security-policy": {
        "name": "CSP",
        "severity": "HIGH",
        "description": "Prevents XSS and injection attacks",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "MEDIUM",
        "description": "Prevents clickjacking",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "description": "Prevents MIME sniffing",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "LOW",
        "description": "Legacy XSS filter (deprecated but still seen)",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "LOW",
        "description": "Controls referrer information",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "MEDIUM",
        "description": "Controls browser feature access",
    },
    "x-permitted-cross-domain-policies": {
        "name": "X-Permitted-Cross-Domain-Policies",
        "severity": "LOW",
        "description": "Controls cross-domain data access",
    },
}


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Analyse HTTP headers of a target URL.

    Params:
        target: URL or domain (e.g. "example.com" or "https://example.com")
        follow_redirects: Whether to follow redirects (default: true)
    """
    target = params.get("target", "")

    if not target:
        print("[ERROR] No target specified")
        return {"error": "No target specified"}

    # Normalise URL
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    use_ssl = parsed.scheme == "https"

    print(f"[*] HTTP Header Analysis for: {target}")
    print(f"[*] Host: {hostname}:{port} (SSL: {use_ssl})")
    print("=" * 60)

    try:
        # Build raw HTTP request
        request = (
            f"HEAD {path} HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            f"User-Agent: KaliAppHost/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        # Connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        if use_ssl:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=hostname)

        sock.connect((hostname, port))
        sock.send(request.encode())

        # Read response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response:
                break

        sock.close()

        # Parse response
        header_text = response.decode("utf-8", errors="ignore")
        headers = _parse_headers(header_text)
        status_line = header_text.split("\r\n")[0]

        print(f"\n--- Response ---")
        print(f"  Status: {status_line}")

        print(f"\n--- All Headers ---")
        for name, value in headers.items():
            print(f"  {name}: {value}")

        # Security analysis
        print(f"\n--- Security Header Analysis ---")
        present = []
        missing = []

        for header_key, info in SECURITY_HEADERS.items():
            if header_key in headers:
                present.append({
                    "header": info["name"],
                    "value": headers[header_key],
                    "severity": info["severity"],
                })
                print(f"  [+] {info['name']}: {headers[header_key][:80]}")
            else:
                missing.append({
                    "header": info["name"],
                    "severity": info["severity"],
                    "description": info["description"],
                })
                print(f"  [-] {info['name']} MISSING ({info['severity']}) - {info['description']}")

        # Technology fingerprinting
        print(f"\n--- Technology Hints ---")
        tech = _fingerprint_tech(headers)
        for hint in tech:
            print(f"  [*] {hint}")

        score = len(present)
        total = len(SECURITY_HEADERS)
        print(f"\n--- Score ---")
        print(f"  Security headers: {score}/{total}")
        grade = "A" if score >= 7 else "B" if score >= 5 else "C" if score >= 3 else "D" if score >= 1 else "F"
        print(f"  Grade: {grade}")

        print("=" * 60)
        print("[*] Header analysis complete")

        return {
            "url": target,
            "status": status_line,
            "headers": headers,
            "security_present": present,
            "security_missing": missing,
            "technology": tech,
            "score": f"{score}/{total}",
            "grade": grade,
        }

    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}


def _parse_headers(response: str) -> Dict[str, str]:
    """Parse HTTP response headers into a dict."""
    headers = {}
    lines = response.split("\r\n")
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        elif line.strip() == "":
            break
    return headers


def _fingerprint_tech(headers: Dict[str, str]) -> List[str]:
    """Extract technology hints from headers."""
    hints = []

    server = headers.get("server", "")
    if server:
        hints.append(f"Server: {server}")

    powered = headers.get("x-powered-by", "")
    if powered:
        hints.append(f"Powered by: {powered}")

    if "x-aspnet-version" in headers:
        hints.append(f"ASP.NET: {headers['x-aspnet-version']}")

    if "x-drupal" in str(headers):
        hints.append("CMS: Drupal detected")

    if "x-generator" in headers:
        hints.append(f"Generator: {headers['x-generator']}")

    if "set-cookie" in headers:
        cookies = headers["set-cookie"].lower()
        if "phpsessid" in cookies:
            hints.append("Language: PHP detected (PHPSESSID cookie)")
        if "jsessionid" in cookies:
            hints.append("Language: Java detected (JSESSIONID cookie)")
        if "asp.net" in cookies:
            hints.append("Language: ASP.NET detected (ASP.NET cookie)")

    return hints
