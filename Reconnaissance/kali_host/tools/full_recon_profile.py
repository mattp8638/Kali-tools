"""
Full Recon Profile - Orchestrates multiple recon tools for a comprehensive target report.
Accepts domain, IP, email and/or username, runs relevant tools in sequence,
extracts key findings, and exports a CSV and Markdown summary report.
"""
from typing import Dict, Any, Callable, List, Optional
import csv
import importlib
import os
from datetime import datetime
from kali_host.core.api_keys import get_api_key_manager


# ---------------------------------------------------------------------------
# Tool plan: (tool_id, module_path, param_builder_fn)
# ---------------------------------------------------------------------------

def _plan_network(ip: str, domain: str) -> List[tuple]:
    """Network-layer tools (nmap, ping)."""
    plan = []
    target = ip or domain
    if target:
        plan.append((
            "nmap_scan",
            "kali_host.tools.nmap_scan",
            {
                "target": target,
                "scan_type": "SYN",
                "service_versions": True,
                "os_detect": False,
            },
        ))
    return plan


def _plan_dns(domain: str) -> List[tuple]:
    """DNS tools."""
    if not domain:
        return []
    return [
        (
            "dns_recon",
            "kali_host.tools.dns_recon",
            {"target": domain, "record_types": "A,AAAA,MX,NS,TXT,SOA,CNAME"},
        ),
        (
            "subdomain_enum",
            "kali_host.tools.subdomain_enum",
            {"domain": domain},
        ),
        (
            "whois_lookup",
            "kali_host.tools.whois_lookup",
            {"target": domain},
        ),
    ]


def _plan_web(domain: str, shodan_key: str) -> List[tuple]:
    """Web-layer tools."""
    if not domain:
        return []
    url = domain if domain.startswith("http") else f"https://{domain}"
    plan = [
        (
            "http_headers",
            "kali_host.tools.http_headers",
            {"target": url},
        ),
        (
            "ssl_cert_info",
            "kali_host.tools.ssl_cert_info",
            {"host": domain, "port": 443},
        ),
        (
            "whatweb",
            "kali_host.tools.whatweb",
            {"target": url, "aggression": "1", "follow_redirects": True},
        ),
        (
            "wafw00f",
            "kali_host.tools.wafw00f",
            {"target": url},
        ),
    ]
    return plan


def _plan_osint(domain: str, ip: str, email: str, username: str,
                shodan_key: str, hibp_key: str) -> List[tuple]:
    """OSINT-layer tools."""
    plan = []
    if domain:
        plan.append((
            "theharvester",
            "kali_host.tools.theharvester",
            {
                "target": domain,
                "sources": "all",
                "limit": 200,
                "dns_lookup": False,
            },
        ))
    if ip and shodan_key:
        plan.append((
            "shodan_recon",
            "kali_host.tools.shodan_recon",
            {"ip_or_domain": ip, "api_key": shodan_key},
        ))
    elif domain and shodan_key:
        plan.append((
            "shodan_recon",
            "kali_host.tools.shodan_recon",
            {"ip_or_domain": domain, "api_key": shodan_key},
        ))
    if email:
        plan.append((
            "email_osint",
            "kali_host.tools.email_osint",
            {
                "email": email,
                "check_dns": True,
                "check_social": True,
                "check_ct": True,
                "check_breaches": bool(hibp_key),
                "hibp_api_key": hibp_key,
            },
        ))
    if username:
        plan.append((
            "username_osint_plus",
            "kali_host.tools.username_osint_plus",
            {
                "username": username,
                "run_sherlock": True,
                "check_github": True,
                "check_keybase": True,
                "check_hackernews": True,
                "check_npm": True,
                "check_pypi": True,
            },
        ))
    return plan


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Full Recon Profile - run all applicable tools and produce a report.

    Params:
        domain: Target domain (e.g. "example.com")
        ip: Target IP address
        email: Target email address
        username: Target username
        run_network: Boolean, include network scan (default True)
        run_dns: Boolean, include DNS tools (default True)
        run_web: Boolean, include web tools (default True)
        run_osint: Boolean, include OSINT tools (default True)
        shodan_api_key: Shodan API key (optional)
        hibp_api_key: HaveIBeenPwned API key (optional)
        output_dir: Custom output directory (optional)
    """
    domain = params.get("domain", "").strip()
    ip = params.get("ip", "").strip()
    email = params.get("email", "").strip()
    username = params.get("username", "").strip()

    run_network = bool(params.get("run_network", True))
    run_dns = bool(params.get("run_dns", True))
    run_web = bool(params.get("run_web", True))
    run_osint = bool(params.get("run_osint", True))

    shodan_key = params.get("shodan_api_key", "").strip() or _get_shodan_key()
    hibp_key = params.get("hibp_api_key", "").strip() or _get_hibp_key()

    custom_output_dir = params.get("output_dir", "").strip()

    if not any([domain, ip, email, username]):
        print("[ERROR] At least one target (domain, IP, email, or username) is required")
        return {"error": "No target specified"}

    master: Dict[str, Any] = {
        "target": {
            "domain": domain,
            "ip": ip,
            "email": email,
            "username": username,
        },
        "tools_run": [],
        "results": {},
        "findings": [],
        "csv_path": None,
        "report_path": None,
    }

    print("[*] Full Recon Profile starting")
    print(f"    Domain:   {domain or '(none)'}")
    print(f"    IP:       {ip or '(none)'}")
    print(f"    Email:    {email or '(none)'}")
    print(f"    Username: {username or '(none)'}")
    print("=" * 60)

    tool_plan: List[tuple] = []
    if run_network:
        tool_plan.extend(_plan_network(ip, domain))
    if run_dns:
        tool_plan.extend(_plan_dns(domain))
    if run_web:
        tool_plan.extend(_plan_web(domain, shodan_key))
    if run_osint:
        tool_plan.extend(_plan_osint(domain, ip, email, username, shodan_key, hibp_key))

    if not tool_plan:
        print("[!] No tools applicable to the given targets and toggles")
        return {"error": "No tools to run"}

    total = len(tool_plan)
    print(f"[*] Tools to run: {total}\n")

    for idx, (tool_id, module_path, tool_params) in enumerate(tool_plan, 1):
        if is_cancelled and is_cancelled():
            print("\n[!] Full Recon Profile cancelled")
            break

        print(f"\n{'='*60}")
        print(f"[*] Step {idx}/{total}: {tool_id}")
        print(f"{'='*60}")

        try:
            mod = importlib.import_module(module_path)
            result = mod.run(
                tool_params,
                on_progress=None,
                on_output=on_output,
                is_cancelled=is_cancelled,
            )
            master["results"][tool_id] = result
            master["tools_run"].append(tool_id)
            _extract_findings(tool_id, result, master["findings"])
        except Exception as e:
            print(f"[!] {tool_id} failed: {e}")
            master["results"][tool_id] = {"error": str(e)}

        if on_progress:
            on_progress(idx, total)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    out_dir = custom_output_dir or os.path.join(os.path.expanduser("~"), ".kali_tools_temp")
    os.makedirs(out_dir, exist_ok=True)

    target_slug = (domain or ip or email or username or "scan")
    target_slug = (
        target_slug.replace(".", "_")
                   .replace("@", "_at_")
                   .replace("/", "_")
                   .replace(":", "_")
    )
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    csv_path = os.path.join(out_dir, f"recon_{target_slug}_{timestamp}.csv")
    report_path = os.path.join(out_dir, f"recon_{target_slug}_{timestamp}.md")

    _export_csv(master["findings"], csv_path)
    _export_markdown(master, report_path, timestamp)

    master["csv_path"] = csv_path
    master["report_path"] = report_path

    print(f"\n{'='*60}")
    print("[+] Full Recon Profile complete")
    print(f"[+] Tools run:     {len(master['tools_run'])}")
    print(f"[+] Total findings:{len(master['findings'])}")
    print(f"[+] CSV:           {csv_path}")
    print(f"[+] Report:        {report_path}")
    print("=" * 60)

    return master


# ---------------------------------------------------------------------------
# Finding extractor
# ---------------------------------------------------------------------------

def _extract_findings(tool_id: str, result: Any, findings: List[Dict]) -> None:
    """Normalise tool results into a flat list of findings rows."""
    if not isinstance(result, dict) or result.get("error"):
        return

    # dns_recon
    if tool_id in ("dns_recon",):
        for rtype, values in result.get("records", {}).items():
            for v in (values or []):
                _add(findings, tool_id, "dns", rtype, str(v))

    # dnsrecon_advanced
    if tool_id in ("dnsrecon_advanced",):
        for rec in result.get("records", []):
            _add(findings, tool_id, "dns", rec.get("type", "?"), rec.get("value", ""), extra={"name": rec.get("name")})

    # subdomain_enum, theharvester_subdomains, theharvester
    if tool_id in ("subdomain_enum", "theharvester_subdomains"):
        for h in result.get("subdomains", []) + result.get("hosts", []):
            _add(findings, tool_id, "subdomain", "host", str(h))
    if tool_id == "theharvester":
        for h in result.get("hosts", []):
            _add(findings, tool_id, "subdomain", "host", str(h))
        for e in result.get("emails", []):
            _add(findings, tool_id, "email", "harvested", str(e))

    # whois_lookup
    if tool_id == "whois_lookup":
        for key in ("registrar", "creation_date", "expiration_date"):
            val = result.get(key)
            if val:
                _add(findings, tool_id, "whois", key, str(val))

    # nmap_scan / nmap_scanner
    if tool_id in ("nmap_scan", "nmap_scanner"):
        for p in result.get("ports", []) + result.get("open_ports", []):
            if isinstance(p, dict):
                state = p.get("state", "open")
                if state == "open":
                    value = f"{p.get('ip', '')}:{p.get('port')}/{p.get('protocol', 'tcp')}"
                    _add(findings, tool_id, "port", "open", value,
                         extra={"service": p.get("service") or p.get("service", "")})

    # ssl_cert_info
    if tool_id == "ssl_cert_info":
        days = result.get("days_left")
        if days is not None:
            status = "expired" if result.get("expired") else ("expiring_soon" if days <= 30 else "valid")
            _add(findings, tool_id, "ssl", "expiry", f"{days} days ({status})")
        for san in result.get("san", []):
            _add(findings, tool_id, "ssl", "san", san)
        cipher = result.get("cipher", {})
        if cipher.get("name"):
            _add(findings, tool_id, "ssl", "cipher", cipher["name"])

    # http_headers
    if tool_id == "http_headers":
        for flag in result.get("missing_headers", []):
            _add(findings, tool_id, "http", "missing_header", str(flag))

    # wafw00f / wafw00f_scan
    if tool_id in ("wafw00f", "wafw00f_scan"):
        if result.get("waf_detected"):
            _add(findings, tool_id, "waf", "detected", result.get("waf_name") or "unknown")

    # shodan_recon
    if tool_id == "shodan_recon":
        host = result.get("host", {})
        for p in host.get("ports", []):
            _add(findings, tool_id, "shodan", "port",
                 f"{host.get('ip', '')}:{p.get('port')}",
                 extra={"product": p.get("product"), "org": host.get("org")})
        for cve in host.get("vulns", []):
            _add(findings, tool_id, "shodan", "vuln", cve)
        for match in result.get("matches", []):
            _add(findings, tool_id, "shodan", "search",
                 f"{match.get('ip')}:{match.get('port')}",
                 extra={"product": match.get("product"), "org": match.get("org")})

    # email_osint
    if tool_id == "email_osint":
        for breach in result.get("breaches", []):
            _add(findings, tool_id, "breach", "hibp", breach.get("Name", ""))
        for sub in result.get("ct_subdomains", []):
            _add(findings, tool_id, "subdomain", "ct_log", sub)
        for sig in result.get("social_signals", []):
            _add(findings, tool_id, "social", "signal", str(sig))
        dns = result.get("dns", {})
        if not dns.get("spf"):
            _add(findings, tool_id, "email_security", "missing", "SPF record")
        if not dns.get("dmarc"):
            _add(findings, tool_id, "email_security", "missing", "DMARC record")

    # username_osint_plus / sherlock
    if tool_id in ("username_osint_plus", "sherlock"):
        for p in result.get("sherlock_profiles", []) + result.get("found", []):
            _add(findings, tool_id, "social", "profile", p.get("url", ""),
                 extra={"platform": p.get("platform", "")})
        if result.get("github", {}).get("found"):
            _add(findings, tool_id, "social", "profile",
                 result["github"].get("url", ""), extra={"platform": "GitHub"})


def _add(findings: List[Dict], source: str, category: str,
         finding_type: str, value: str, extra: Dict = None) -> None:
    row = {
        "source": source,
        "category": category,
        "type": finding_type,
        "value": value,
    }
    if extra:
        row.update(extra)
    findings.append(row)


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def _export_csv(findings: List[Dict], path: str) -> None:
    if not findings:
        return
    # Gather all field names (preserve order: fixed cols first, extras last)
    fixed = ["source", "category", "type", "value"]
    extra_keys: List[str] = []
    for row in findings:
        for k in row:
            if k not in fixed and k not in extra_keys:
                extra_keys.append(k)
    fieldnames = fixed + extra_keys

    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(findings)
        print(f"[+] CSV exported: {path}")
    except Exception as e:
        print(f"[!] CSV export error: {e}")


def _export_markdown(master: Dict, path: str, timestamp: str) -> None:
    target = master["target"]
    findings = master["findings"]
    tools_run = master["tools_run"]
    results = master["results"]

    # Group findings by category
    by_category: Dict[str, List[Dict]] = {}
    for row in findings:
        cat = row.get("category", "other")
        by_category.setdefault(cat, []).append(row)

    lines = [
        f"# Recon Report",
        f"",
        f"**Generated:** {timestamp}  ",
        f"**Domain:** {target.get('domain') or '—'}  ",
        f"**IP:** {target.get('ip') or '—'}  ",
        f"**Email:** {target.get('email') or '—'}  ",
        f"**Username:** {target.get('username') or '—'}  ",
        f"",
        f"## Summary",
        f"",
        f"| Category | Count |",
        f"|----------|-------|",
    ]

    for cat, rows in sorted(by_category.items()):
        lines.append(f"| {cat} | {len(rows)} |")

    lines += [
        f"",
        f"**Total findings:** {len(findings)}  ",
        f"**Tools run:** {', '.join(tools_run)}  ",
        f"",
        f"---",
        f"",
    ]

    # Red-flag section
    red_flags = [
        r for r in findings
        if r.get("category") in ("breach", "waf", "shodan")
        and r.get("type") in ("hibp", "detected", "vuln")
    ]
    ssl_issues = [
        r for r in findings
        if r.get("category") == "ssl" and r.get("type") == "expiry"
        and ("expired" in str(r.get("value", "")) or "expiring_soon" in str(r.get("value", "")))
    ]
    email_sec = [r for r in findings if r.get("category") == "email_security"]

    if red_flags or ssl_issues or email_sec:
        lines.append("## ⚠ Notable Findings")
        lines.append("")
        for r in red_flags + ssl_issues + email_sec:
            lines.append(f"- **[{r.get('category')} / {r.get('type')}]** {r.get('value')}")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Per-category detail
    for cat, rows in sorted(by_category.items()):
        lines.append(f"## {cat.replace('_', ' ').title()}")
        lines.append("")
        for r in rows[:50]:  # cap per section to avoid huge files
            extra_parts = [
                f"{k}: {v}"
                for k, v in r.items()
                if k not in ("source", "category", "type", "value") and v
            ]
            extra_str = f"  _{', '.join(extra_parts)}_" if extra_parts else ""
            lines.append(f"- **{r.get('type')}**: `{r.get('value')}`  (source: {r.get('source')}){extra_str}")
        if len(rows) > 50:
            lines.append(f"- _(and {len(rows) - 50} more — see CSV)_")
        lines.append("")

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[+] Report exported: {path}")
    except Exception as e:
        print(f"[!] Report export error: {e}")


# ---------------------------------------------------------------------------
# API Key Helpers
# ---------------------------------------------------------------------------

def _get_shodan_key() -> str:
    """Get Shodan API key from APIKeyManager."""
    try:
        mgr = get_api_key_manager()
        return mgr.get_key("shodan") or ""
    except Exception:
        return ""


def _get_hibp_key() -> str:
    """Get HIBP API key from APIKeyManager."""
    try:
        mgr = get_api_key_manager()
        return mgr.get_key("hibp") or ""
    except Exception:
        return ""
