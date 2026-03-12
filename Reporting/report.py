"""
Report Tool
Generate a pentest report from tool findings.
Calls report_engine to produce HTML, JSON, TXT or PDF output.
All output paths are Windows-compatible (os.path).
"""
import json
import os
from typing import Any, Callable, Dict, List, Optional

from report_engine import generate


def run(
    params: Dict[str, Any],
    on_progress: Optional[Callable] = None,
    on_output: Optional[Callable] = None,
    is_cancelled: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Generate a pentest report.

    Params:
        title:            Report title
        target:           Target host / engagement scope
        operator:         Tester name / team
        output_format:    html | json | txt | pdf
        output_path:      Full Windows path to write report file
        findings_json:    JSON string of findings array, OR a path to a
                          JSON file exported by a previous tool run
        severity_filter:  all | critical | high_plus
        auto_open:        Open report in default browser/viewer on Windows
    """
    title           = params.get("title", "Pentest Report").strip()
    target          = params.get("target", "").strip()
    operator        = params.get("operator", "").strip()
    output_format   = params.get("output_format", "html").strip().lower()
    output_path     = params.get("output_path", "").strip()
    findings_raw    = params.get("findings_json", "").strip()
    severity_filter = params.get("severity_filter", "all").strip().lower()
    auto_open       = bool(params.get("auto_open", True))

    # Default output path — Windows Desktop
    if not output_path:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        safe_title = "".join(c if c.isalnum() or c in " _-" else "_" for c in title)
        ext = output_format if output_format != "html" else "html"
        output_path = os.path.join(desktop, f"{safe_title}.{ext}")

    result: Dict[str, Any] = {
        "findings": [],
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "output_path": output_path,
        "status": "",
    }

    _emit(on_output, f"[*] Report Generator")
    _emit(on_output, f"[*] Title:    {title}")
    _emit(on_output, f"[*] Target:   {target or 'N/A'}")
    _emit(on_output, f"[*] Format:   {output_format.upper()}")
    _emit(on_output, f"[*] Output:   {output_path}")
    _emit(on_output, "=" * 60)

    if on_progress:
        on_progress(10, 100)

    findings = _load_findings(findings_raw, on_output)
    if not findings:
        _emit(on_output, "[!] No findings provided — generating empty report.")

    result["findings"] = findings

    if on_progress:
        on_progress(40, 100)

    try:
        gen = generate(
            findings=findings,
            output_format=output_format,
            output_path=output_path,
            title=title,
            target=target,
            operator=operator,
            severity_filter=severity_filter,
            auto_open=auto_open,
            on_output=on_output,
        )
        result["status"]      = gen["status"]
        result["output_path"] = gen["path"]
        if "meta" in gen:
            result["severity_counts"] = gen["meta"]["counts"]
    except Exception as e:
        result["status"] = f"error: {e}"
        _emit(on_output, f"[!] {e}")

    if on_progress:
        on_progress(100, 100)

    _emit(on_output, "\n" + "=" * 60)
    _emit(on_output, f"[+] Status: {result['status']}")
    _emit(on_output, f"[+] Report: {result['output_path']}")
    return result


def _load_findings(raw: str, on_output) -> List[Dict]:
    if not raw:
        return []
    if os.path.exists(raw):
        _emit(on_output, f"[*] Loading findings from file: {raw}")
        try:
            with open(raw, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "findings" in data:
                return data["findings"]
        except Exception as e:
            _emit(on_output, f"[!] Failed to load findings file: {e}")
            return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "findings" in data:
            return data["findings"]
    except Exception:
        pass
    _emit(on_output, "[!] Could not parse findings_json")
    return []


def _emit(on_output, msg):
    print(msg)
    if on_output:
        on_output(msg)
