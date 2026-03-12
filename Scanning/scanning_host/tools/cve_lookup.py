from typing import Any, Callable, Dict, List

import requests


def _nvd_search(keyword: str, limit: int = 10) -> List[Dict[str, Any]]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": limit}
    r = requests.get(url, params=params, timeout=20)
    r.raise_for_status()
    data = r.json()
    rows = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        metrics = cve.get("metrics", {})
        score = None
        vector = None
        severity = None
        metric_rows = []
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_rows = metrics.get(key, [])
            if metric_rows:
                cvss_data = metric_rows[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                vector = cvss_data.get("vectorString")
                severity = cvss_data.get("baseSeverity") or metric_rows[0].get("baseSeverity")
                break

        references = []
        for ref in cve.get("references", [])[:5]:
            if ref.get("url"):
                references.append(ref.get("url"))

        rows.append({
            "cve_id": cve_id,
            "score": score,
            "severity": severity,
            "vector": vector,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": desc,
            "references": references,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
        })
    return rows


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    query = str(params.get("query", "")).strip()
    limit = int(params.get("limit", 10))
    if not query:
        return {"error": "query is required (e.g. 'OpenSSH 8.2' or 'Apache 2.4.49')"}

    print("[*] CVE lookup starting")
    print(f"[*] Query: {query} | Limit: {limit}")
    hits = _nvd_search(query, limit=limit)
    print(f"[*] CVE lookup complete: {len(hits)} result(s)")
    for row in hits[:5]:
        print(f"[+] {row.get('cve_id')} score={row.get('score')}")
    return {"query": query, "count": len(hits), "results": hits}
