"""
Sublist3r Scan - Fast passive subdomain enumeration using multiple search engines.
Uses the sublist3r Python library directly, no CLI needed.
All search engines are queried concurrently and results are deduplicated.
"""
import threading
from typing import Dict, Any, Callable, List, Set


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run Sublist3r subdomain enumeration.

    Params:
        domain: Target domain (e.g. "example.com")
        engines: Comma-separated engines to use, or "all"
        threads: Thread count for brute-force (default 30)
        ports: Optional port list to check (e.g. "80,443")
        enable_bruteforce: Boolean, enable brute-force enumeration
        verbose: Boolean, verbose output
    """
    domain = params.get("domain", "").strip()
    engines_str = params.get("engines", "all").strip()
    threads = int(params.get("threads", 30))
    ports_str = params.get("ports", "").strip()
    enable_bruteforce = bool(params.get("enable_bruteforce", False))
    verbose = bool(params.get("verbose", True))

    if not domain:
        print("[ERROR] No domain specified")
        return {"error": "No domain specified", "subdomains": []}

    # Strip leading www.
    if domain.startswith("www."):
        domain = domain[4:]

    all_engines = [
        "baidu", "yahoo", "google", "bing", "ask",
        "netcraft", "dnsdumpster", "virustotal",
        "threatcrowd", "ssl", "passivedns"
    ]

    if engines_str.lower() == "all" or not engines_str:
        chosen_engines = all_engines
    else:
        chosen_engines = [e.strip().lower() for e in engines_str.split(",") if e.strip()]

    ports: List[int] = []
    if ports_str:
        for p in ports_str.split(","):
            p = p.strip()
            if p.isdigit():
                ports.append(int(p))

    print(f"[*] Sublist3r starting for: {domain}")
    print(f"[*] Engines: {', '.join(chosen_engines)}")
    print(f"[*] Brute-force: {'yes' if enable_bruteforce else 'no'}")
    print(f"[*] Threads: {threads}")
    if ports:
        print(f"[*] Port scan: {ports_str}")
    print("=" * 60)

    results: Dict[str, Any] = {
        "domain": domain,
        "subdomains": [],
        "source_counts": {},
        "total_found": 0,
    }

    try:
        import sublist3r
    except ImportError:
        print("[ERROR] sublist3r not installed.")
        print("[*] Run: pip install sublist3r")
        return {"error": "sublist3r package not installed", "subdomains": []}

    if is_cancelled and is_cancelled():
        print("[!] Cancelled before start")
        return results

    try:
        # sublist3r.main() returns a list of subdomains
        # signature: main(domain, threads, savefile, ports, silent, verbose, enable_bruteforce, engines)
        # 'silent=True' suppresses sublist3r's own banner so we control output
        subdomains_raw: List[str] = sublist3r.main(
            domain=domain,
            threads=threads,
            savefile=None,
            ports=ports if ports else None,
            silent=False,  # let sublist3r print its own output to stdout
            verbose=verbose,
            enable_bruteforce=enable_bruteforce,
            engines=chosen_engines if engines_str.lower() != "all" else None,
        )
    except Exception as e:
        print(f"[ERROR] Sublist3r error: {e}")
        return {"error": str(e), "subdomains": []}

    if not subdomains_raw:
        subdomains_raw = []

    # Deduplicate and sort
    unique: Set[str] = set()
    clean: List[str] = []
    for s in subdomains_raw:
        s = s.strip().lower()
        if s and s not in unique:
            unique.add(s)
            clean.append(s)
    clean.sort()

    results["subdomains"] = clean
    results["total_found"] = len(clean)

    print("\n" + "=" * 60)
    print(f"[+] Sublist3r found {len(clean)} unique subdomain(s)")
    if clean:
        print(f"\n{'SUBDOMAIN':<55}")
        print("-" * 60)
        for s in clean:
            print(f"  [+] {s}")
    print("=" * 60)
    print("[*] Sublist3r scan complete")

    return results
