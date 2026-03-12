"""
Email Format / Pattern Discovery - Discover email naming conventions for a domain.
Takes a domain and discovers the email format in use (first.last@, f.last@, etc.)
via Hunter.io pattern endpoint, email permutation testing, and LinkedIn inference.
Feeds into phishing, social engineering, and targeted recon.
"""
import json
import re
import urllib.parse
from typing import Dict, Any, Callable, List, Optional
from kali_host.core.api_keys import get_api_key_manager


# Email pattern templates (using placeholder vars: {first}, {last}, {f}, {l})
PATTERN_TEMPLATES = {
    "{first}.{last}":   "First.Last (e.g. john.smith@)",
    "{first}{last}":    "FirstLast (e.g. johnsmith@)",
    "{f}{last}":        "FLast (e.g. jsmith@)",
    "{f}.{last}":       "F.Last (e.g. j.smith@)",
    "{first}":          "First only (e.g. john@)",
    "{last}":           "Last only (e.g. smith@)",
    "{last}{first}":    "LastFirst (e.g. smithjohn@)",
    "{last}.{first}":   "Last.First (e.g. smith.john@)",
    "{first}_{last}":   "First_Last (e.g. john_smith@)",
    "{last}{f}":        "LastF (e.g. smithj@)",
    "{first}{l}":       "FirstL (e.g. johns@)",
    "{f}{l}":           "FL initials (e.g. js@)",
}

# Common first/last name pairs for format testing
TEST_NAMES = [
    ("john", "smith"),
    ("jane", "doe"),
    ("michael", "johnson"),
    ("sarah", "williams"),
]


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Discover email naming patterns and enumerate likely email addresses for a domain.

    Params:
        domain: Target domain (e.g. example.com)
        names: Known names to generate emails for (CSV: "First Last, First Last, ...")
        hunter_api_key: Hunter.io API key (optional but recommended)
        generate_permutations: Generate all format permutations for provided names (default: true)
        verify_smtp: Attempt SMTP verification of generated addresses (default: false)
    """
    domain = params.get("domain", "").strip().lower()
    if domain.startswith("http"):
        domain = re.sub(r'https?://', '', domain).split('/')[0]

    names_raw = params.get("names", "").strip()
    hunter_key = params.get("hunter_api_key", "").strip() or _get_hunter_key()
    generate_perms = str(params.get("generate_permutations", "true")).lower() not in ("false", "0", "no")

    if not domain:
        print("[ERROR] A domain is required (e.g. example.com)")
        return {"error": "No domain provided"}

    # Parse names list
    names = []
    if names_raw:
        for n in names_raw.split(","):
            n = n.strip()
            parts = n.split()
            if len(parts) >= 2:
                names.append({"first": parts[0].lower(), "last": parts[-1].lower()})
            elif len(parts) == 1:
                names.append({"first": parts[0].lower(), "last": ""})

    print(f"[*] Email Format Discovery for: {domain}")
    print(f"[*] Names provided: {len(names)}")
    print("=" * 60)

    results: Dict[str, Any] = {
        "domain": domain,
        "detected_pattern": None,
        "pattern_confidence": None,
        "pattern_description": None,
        "hunter_emails": [],
        "generated_emails": [],
        "all_formats": list(PATTERN_TEMPLATES.keys()),
    }

    total_steps = 3
    step = 0

    def _prog():
        nonlocal step
        step += 1
        if on_progress:
            on_progress(step, total_steps)

    # ------------------------------------------------------------------
    # 1. Hunter.io domain search (best source of truth)
    # ------------------------------------------------------------------
    print("\n--- Hunter.io Domain Search ---")
    if hunter_key:
        domain_data = _hunter_domain_search(domain, hunter_key)

        if domain_data.get("pattern"):
            pattern = domain_data["pattern"]
            results["detected_pattern"] = pattern
            print(f"  [+] Detected pattern: {pattern.replace('{', '{{').replace('}', '}}')}")
            # Map to our template description
            if pattern in PATTERN_TEMPLATES:
                results["pattern_description"] = PATTERN_TEMPLATES[pattern]
                print(f"      Format: {PATTERN_TEMPLATES[pattern]}")

        emails = domain_data.get("emails", [])
        if emails:
            print(f"  [+] Found {len(emails)} email(s) via Hunter.io:")
            for em in emails:
                addr = em.get("value", "")
                confidence = em.get("confidence", 0)
                source = em.get("sources", [{}])[0].get("domain", "") if em.get("sources") else ""
                dept = em.get("department", "")
                position = em.get("position", "")
                
                label_parts = [addr]
                if confidence:
                    label_parts.append(f"conf:{confidence}%")
                if dept:
                    label_parts.append(dept)
                if position:
                    label_parts.append(position)
                
                print(f"      {' | '.join(label_parts)}")
                results["hunter_emails"].append({
                    "email": addr,
                    "confidence": confidence,
                    "department": dept,
                    "position": position,
                    "source": source,
                })

        total_count = domain_data.get("total", 0)
        if total_count:
            print(f"  [+] Total emails Hunter.io knows about: {total_count}")

    else:
        print("  [-] No Hunter.io API key — skipping (add key in Settings > API Keys)")

    _prog()

    # ------------------------------------------------------------------
    # 2. Hunter.io email finder for named individuals
    # ------------------------------------------------------------------
    if hunter_key and names:
        print("\n--- Hunter.io Email Finder ---")
        for person in names:
            if is_cancelled and is_cancelled():
                break
            first = person["first"]
            last = person["last"]
            if not last:
                continue
            
            result = _hunter_email_finder(first, last, domain, hunter_key)
            if result:
                email = result.get("email", "")
                score = result.get("score", 0)
                if email:
                    print(f"  [+] {first.capitalize()} {last.capitalize()}: {email} (confidence: {score}%)")
                    results["generated_emails"].append({
                        "name": f"{first} {last}",
                        "email": email,
                        "source": "hunter_finder",
                        "confidence": score,
                    })
            else:
                print(f"  [-] {first.capitalize()} {last.capitalize()}: not found")

    _prog()

    # ------------------------------------------------------------------
    # 3. Generate email permutations for provided names
    # ------------------------------------------------------------------
    if generate_perms and names:
        print("\n--- Email Permutation Generation ---")
        detected = results.get("detected_pattern")

        for person in names:
            first = person["first"]
            last = person["last"]
            if not first:
                continue

            print(f"\n  {first.capitalize()} {last.capitalize() if last else ''}:")

            # If we have a detected pattern, show that first
            if detected and last:
                primary = _apply_pattern(detected, first, last, domain)
                print(f"    [*] Most likely: {primary}  (matched pattern)")

            # Generate all permutations
            for template, description in PATTERN_TEMPLATES.items():
                if not last and ("{last}" in template or "{l}" in template):
                    continue
                email = _apply_pattern(template, first, last, domain)
                already_listed = any(g["email"] == email for g in results["generated_emails"])
                if not already_listed:
                    results["generated_emails"].append({
                        "name": f"{first} {last}".strip(),
                        "email": email,
                        "source": "permutation",
                        "pattern": template,
                        "confidence": 100 if template == detected else None,
                    })
                flag = " <-- likely" if template == detected else ""
                print(f"    {email}{flag}")

    _prog()

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"[*] Email pattern discovery complete for: {domain}")
    if results["detected_pattern"]:
        print(f"    Pattern: {results['detected_pattern']}  ({results.get('pattern_description', '')})")
    else:
        print(f"    Pattern: Not definitively detected")
    print(f"    Hunter emails:    {len(results['hunter_emails'])}")
    print(f"    Generated emails: {len(results['generated_emails'])}")
    print("=" * 60)

    return results


# ---------------------------------------------------------------------------
# Hunter.io API
# ---------------------------------------------------------------------------

def _hunter_domain_search(domain: str, api_key: str) -> Dict:
    """Search Hunter.io for all known emails and detected pattern for a domain."""
    try:
        from urllib.request import Request, urlopen
        url = "https://api.hunter.io/v2/domain-search"
        params = {
            "domain": domain,
            "api_key": api_key,
            "limit": 100,
        }
        req = Request(url + "?" + urllib.parse.urlencode(params))
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8")).get("data", {})
    except Exception:
        return {}


def _hunter_email_finder(first: str, last: str, domain: str, api_key: str) -> Optional[Dict]:
    """Use Hunter.io Email Finder for a specific person."""
    try:
        from urllib.request import Request, urlopen
        url = "https://api.hunter.io/v2/email-finder"
        params = {
            "first_name": first,
            "last_name": last,
            "domain": domain,
            "api_key": api_key,
        }
        req = Request(url + "?" + urllib.parse.urlencode(params))
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8")).get("data", {})
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Email Generation
# ---------------------------------------------------------------------------

def _apply_pattern(template: str, first: str, last: str, domain: str) -> str:
    """Apply a pattern template to generate an email address."""
    f = first[0] if first else ""
    l = last[0] if last else ""
    email = template.format(first=first, last=last, f=f, l=l)
    return f"{email}@{domain}"


def _get_hunter_key() -> str:
    try:
        return get_api_key_manager().get_key("hunter") or ""
    except Exception:
        return ""
