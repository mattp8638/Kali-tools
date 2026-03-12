import concurrent.futures
from typing import Any, Callable, Dict, List

import requests

from scanning_host.core.common import normalize_url, safe_int

DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "backup", "uploads", "api", "config", "test",
    "dev", "staging", "old", "private", "robots.txt", "sitemap.xml", ".env", ".git",
]


def _probe(url: str, timeout: int) -> Dict[str, Any]:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False)
        return {"url": url, "status": r.status_code, "length": len(r.text)}
    except Exception as e:
        return {"url": url, "error": str(e)}


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    target = normalize_url(params.get("target", ""))
    timeout = safe_int(params.get("timeout", 5), 5)
    threads = safe_int(params.get("threads", 20), 20)
    words = params.get("wordlist", "").strip()

    if not target:
        return {"error": "target is required"}

    print("[*] Directory scan starting")
    print(f"[*] Target: {target}")
    print(f"[*] Threads: {threads} | Timeout: {timeout}s")

    candidates = [w.strip() for w in words.split(",") if w.strip()] if words else DEFAULT_WORDLIST
    urls = [f"{target.rstrip('/')}/{w}" for w in candidates]
    print(f"[*] Paths to test: {len(urls)}")

    hits: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_probe, u, timeout) for u in urls]
        for idx, fut in enumerate(concurrent.futures.as_completed(futures), start=1):
            if is_cancelled and is_cancelled():
                break
            if on_progress:
                on_progress(idx, len(urls))
            row = fut.result()
            if "status" in row and row["status"] not in (404,):
                hits.append(row)
                print(f"[+] {row['status']} {row['url']} (len={row.get('length', 0)})")

    hits.sort(key=lambda x: x.get("status", 999))
    print(f"[*] Directory scan complete: {len(hits)} hit(s) from {len(urls)} tested path(s)")
    return {"target": target, "tested": len(urls), "hits": hits, "hit_count": len(hits)}
