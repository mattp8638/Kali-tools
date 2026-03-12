import json
from typing import Any, Callable, Dict, List

from scanning_host.core.common import normalize_url, resolve_command, resolve_perl_script, run_command, safe_int


def _extract_json_payload(stdout: str) -> Any:
    raw = (stdout or "").strip()
    if not raw:
        return None

    # Nikto can include banner lines around JSON in some environments.
    for start_char, end_char in (("{", "}"), ("[", "]")):
        start = raw.find(start_char)
        end = raw.rfind(end_char)
        if start >= 0 and end > start:
            candidate = raw[start:end + 1]
            try:
                return json.loads(candidate)
            except Exception:
                continue
    return None


def _normalize_findings(payload: Any) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not isinstance(payload, (dict, list)):
        return findings

    rows: List[Dict[str, Any]] = []
    if isinstance(payload, dict):
        for key in ("vulnerabilities", "findings", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                rows = [v for v in value if isinstance(v, dict)]
                break
    elif isinstance(payload, list):
        rows = [v for v in payload if isinstance(v, dict)]

    for row in rows:
        findings.append({
            "id": row.get("id") or row.get("plugin_id") or row.get("nikto_id"),
            "method": row.get("method") or row.get("http_method"),
            "url": row.get("url") or row.get("uri") or row.get("path"),
            "msg": row.get("msg") or row.get("message") or row.get("description"),
            "osvdbid": row.get("osvdbid") or row.get("osvdb"),
            "severity": row.get("severity"),
            "raw": row,
        })
    return findings


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    target = normalize_url(params.get("target", ""))
    timeout = safe_int(params.get("timeout", 600), 600)

    if not target:
        return {"error": "target is required"}

    nikto = resolve_command(["nikto.bat", "nikto"])
    if nikto:
        cmd_prefix = [nikto]
    else:
        pl_path = r"C:\tools\nikto\program\nikto.pl"
        cmd_prefix = resolve_perl_script(pl_path)
        if not cmd_prefix:
            return {
                "error": "Nikto CLI not found. Install Nikto (or Perl + nikto.pl) and ensure it is reachable.",
            }

    cmd = cmd_prefix + ["-h", target, "-Format", "json"]
    code, stdout, stderr = run_command(cmd, timeout=timeout)

    payload = _extract_json_payload(stdout)
    findings = _normalize_findings(payload)

    if not findings:
        # Fallback to legacy plus-line extraction if JSON parsing fails.
        for line in stdout.splitlines():
            if line.strip().startswith("+"):
                findings.append({"msg": line.strip()})

    return {
        "target": target,
        "command": cmd,
        "exit_code": code,
        "findings_count": len(findings),
        "findings": findings,
        "parsed_as_json": isinstance(payload, (dict, list)),
        "raw_stdout": stdout,
        "raw_stderr": stderr,
    }
