import json
import os
import shutil
import socket
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple


WIN_KNOWN_PATHS = [
    r"C:\Tools\nuclei",
    r"C:\tools\nikto\program",
    r"C:\Strawberry\perl\bin",
    r"C:\tools\nmap",
    r"C:\Program Files\Nmap",
    r"C:\Program Files (x86)\Nmap",
]


def normalize_host(value: str) -> str:
    host = (value or "").strip()
    if host.startswith("http://"):
        host = host[7:]
    elif host.startswith("https://"):
        host = host[8:]
    return host.split("/")[0]


def normalize_url(value: str) -> str:
    target = (value or "").strip()
    if not target:
        return ""
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
    return target


def resolve_command(candidates: List[str]) -> Optional[str]:
    scripts_dir = os.path.dirname(sys.executable)
    for name in candidates:
        local = os.path.join(scripts_dir, name)
        if os.path.exists(local):
            return local
    for name in candidates:
        hit = shutil.which(name)
        if hit:
            return hit

    if sys.platform == "win32":
        for name in candidates:
            for known_dir in WIN_KNOWN_PATHS:
                full = os.path.join(known_dir, name)
                if os.path.exists(full):
                    return full
    return None


def resolve_perl_script(script_path: str) -> Optional[List[str]]:
    """Resolve a Perl executable and script path for .pl tools on Windows/Linux."""
    perl = resolve_command(["perl.exe", "perl"])
    if perl and os.path.exists(script_path):
        return [perl, script_path]
    return None


def run_command(cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        errors="ignore",
    )
    return proc.returncode, proc.stdout, proc.stderr


def safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def socket_connect(host: str, port: int, timeout: float = 2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def to_json_preview(value: Any, limit: int = 2000) -> str:
    text = json.dumps(value, indent=2, default=str)
    return text[:limit]
