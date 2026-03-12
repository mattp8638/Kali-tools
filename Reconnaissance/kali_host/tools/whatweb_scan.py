"""
WhatWeb - Web technology fingerprinting.
Wraps the whatweb CLI.
"""
import json
import shlex
import subprocess
from typing import Any, Callable, Dict, List


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run WhatWeb.

    Params:
        url: Target URL
        aggressive: Boolean, enable -a 3
        follow_redirects: Boolean, enable -r
        user_agent: Custom User-Agent
        extra_args: Extra CLI args
    """
    url = params.get("url", "")
    aggressive = params.get("aggressive", True)
    follow_redirects = params.get("follow_redirects", True)
    user_agent = params.get("user_agent", "")
    extra_args = params.get("extra_args", "")

    if not url:
        print("[ERROR] No URL specified")
        return {"error": "No URL specified"}

    result: Dict[str, Any] = {
        "url": url,
        "plugins": [],
        "raw_output": "",
    }

    print(f"[*] WhatWeb scan starting for: {url}")
    print(f"[*] Aggressive: {'yes' if aggressive else 'no'}")
    print(f"[*] Follow redirects: {'yes' if follow_redirects else 'no'}")
    print("=" * 60)

    cmd: List[str] = ["whatweb", "--color=never", "--log-json=-"]

    if aggressive:
        cmd.extend(["-a", "3"])
    if follow_redirects:
        cmd.append("-r")
    if user_agent:
        cmd.extend(["-U", user_agent])
    if extra_args:
        cmd.extend(shlex.split(extra_args))

    cmd.append(url)

    print(f"[*] Running command: {' '.join(cmd)}\n")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        raw_lines: List[str] = []
        for line in iter(proc.stdout.readline, ""):
            if is_cancelled and is_cancelled():
                proc.terminate()
                print("\n[!] Scan cancelled")
                break

            line = line.rstrip("\n")
            if line:
                print(line)
                raw_lines.append(line)
                _try_parse_json_line(line, result)

                if on_output:
                    on_output(line)

        proc.wait()
        result["raw_output"] = "\n".join(raw_lines)

        if on_progress:
            on_progress(1, 1)

        print("\n" + "=" * 60)
        print(f"[+] Detected plugins: {len(result['plugins'])}")
        for plugin in result["plugins"]:
            print(f"  {plugin.get('name')} ({plugin.get('version', 'n/a')})")
        print("=" * 60)
        print("[*] WhatWeb scan complete")

    except FileNotFoundError:
        print("[ERROR] whatweb not found on PATH")
        return {"error": "whatweb not installed or not in PATH"}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}

    return result


def _try_parse_json_line(line: str, result: Dict[str, Any]) -> None:
    """If line looks like JSON from --log-json, parse and extract plugins."""
    payload = line.strip()
    if not (payload.startswith("{") and payload.endswith("}")):
        return

    try:
        data = json.loads(payload)
    except Exception:
        return

    plugins = data.get("plugins", {})
    for name, info in plugins.items():
        plugin = {
            "name": name,
            "version": info.get("version") if isinstance(info, dict) else None,
            "description": info.get("description") if isinstance(info, dict) else None,
        }
        if plugin not in result["plugins"]:
            result["plugins"].append(plugin)
