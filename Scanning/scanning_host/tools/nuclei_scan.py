import json
from typing import Any, Dict, List

from scanning_host.core.common import normalize_url, resolve_command, run_command, safe_int


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    target = normalize_url(params.get("target", ""))
    timeout = safe_int(params.get("timeout", 900), 900)
    severity = params.get("severity", "").strip()

    if not target:
        return {"error": "target is required"}

    nuclei = resolve_command(["nuclei.exe", "nuclei"])
    if not nuclei:
        return {"error": "Nuclei CLI not found. Install Nuclei and ensure it is on PATH."}

    cmd = [nuclei, "-u", target, "-jsonl", "-silent"]
    if severity:
        cmd.extend(["-severity", severity])

    code, stdout, stderr = run_command(cmd, timeout=timeout)

    findings: List[Dict[str, Any]] = []
    severity_counts: Dict[str, int] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            info = row.get("info", {}) if isinstance(row, dict) else {}
            severity = str(info.get("severity") or row.get("severity") or "unknown").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            findings.append({
                "template_id": row.get("template-id"),
                "name": info.get("name"),
                "severity": severity,
                "matched_at": row.get("matched-at"),
                "host": row.get("host"),
                "ip": row.get("ip"),
                "curl_command": row.get("curl-command"),
                "raw": row,
            })
        except Exception:
            pass

    return {
        "target": target,
        "command": cmd,
        "exit_code": code,
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "findings": findings,
        "raw_stderr": stderr,
    }
