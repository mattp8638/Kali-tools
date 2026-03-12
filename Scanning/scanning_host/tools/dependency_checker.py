from typing import Any, Dict, List

from scanning_host.core.common import resolve_command


CHECKS = [
    {
        "name": "Nmap",
        "candidates": ["nmap.exe", "nmap"],
    },
    {
        "name": "Nuclei",
        "candidates": ["nuclei.exe", "nuclei"],
    },
    {
        "name": "Nikto",
        "candidates": ["nikto.bat", "nikto", "nikto.pl"],
    },
    {
        "name": "Perl",
        "candidates": ["perl.exe", "perl"],
    },
]


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for idx, check in enumerate(CHECKS, start=1):
        if is_cancelled and is_cancelled():
            break
        if on_progress:
            on_progress(idx, len(CHECKS))

        hit = resolve_command(check["candidates"])
        installed = bool(hit)
        status = "green" if installed else "red"
        rows.append({
            "tool": check["name"],
            "installed": installed,
            "status": status,
            "resolved_path": hit,
            "candidates": check["candidates"],
        })

    missing = [r["tool"] for r in rows if not r["installed"]]
    return {
        "count": len(rows),
        "installed": len(rows) - len(missing),
        "missing": len(missing),
        "missing_tools": missing,
        "checks": rows,
    }
