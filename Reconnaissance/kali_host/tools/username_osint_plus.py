"""
Username OSINT Plus - Consolidated username intelligence.
Runs Sherlock (social media) and checks GitHub, Keybase,
HackerNews, npm, and PyPI presence for a given username.
"""
from typing import Dict, Any, Callable, List, Optional
import os
import re
import sys
import json
import shutil
import subprocess

import requests


_SESSION_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KaliAppHost/1.0"
}


def _get(url: str, timeout: int = 10, params: dict = None) -> Optional[requests.Response]:
    try:
        return requests.get(url, timeout=timeout, params=params, headers=_SESSION_HEADERS)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Combined username OSINT: Sherlock + social platform checks.

    Params:
        username: Target username
        sherlock_timeout: Per-site timeout for Sherlock (default 60s)
        run_sherlock: Boolean, run Sherlock scan (default True)
        check_github: Boolean, query GitHub API (default True)
        check_keybase: Boolean, query Keybase (default True)
        check_hackernews: Boolean, query HackerNews (default True)
        check_npm: Boolean, check npm registry (default True)
        check_pypi: Boolean, check PyPI (default True)
    """
    username = params.get("username", "").strip()
    sherlock_timeout = params.get("sherlock_timeout", 60)
    run_sherlock = params.get("run_sherlock", True)
    check_github = params.get("check_github", True)
    check_keybase = params.get("check_keybase", True)
    check_hackernews = params.get("check_hackernews", True)
    check_npm = params.get("check_npm", True)
    check_pypi = params.get("check_pypi", True)

    if not username:
        print("[ERROR] No username specified")
        return {"error": "No username specified"}

    results: Dict[str, Any] = {
        "username": username,
        "sherlock_profiles": [],
        "github": {},
        "keybase": {},
        "hackernews": {},
        "npm": {},
        "pypi": {},
    }

    print(f"[*] Username OSINT Plus for: {username}")
    print("=" * 60)

    total_steps = sum([run_sherlock, check_github, check_keybase, check_hackernews, check_npm, check_pypi]) or 1
    step = 0

    def _tick():
        nonlocal step
        step += 1
        if on_progress:
            on_progress(step, total_steps)

    # ------------------------------------------------------------------
    # 1. Sherlock
    # ------------------------------------------------------------------
    if run_sherlock and not (is_cancelled and is_cancelled()):
        print("\n--- Sherlock ---")
        sherlock_cmd = _resolve_sherlock_command()
        if sherlock_cmd:
            out_dir = os.path.join(os.path.expanduser("~"), ".kali_tools_temp")
            os.makedirs(out_dir, exist_ok=True)
            json_file = os.path.join(out_dir, f"sherlock_{username}.json")
            cmd = [
                *sherlock_cmd,
                username,
                "--timeout", str(sherlock_timeout),
                "--print-found",
                "--json", json_file,
            ]
            print(f"[*] Command: {' '.join(cmd)}\n")
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                for line in iter(proc.stdout.readline, ""):
                    if is_cancelled and is_cancelled():
                        proc.terminate()
                        print("\n[!] Sherlock cancelled")
                        break
                    line = line.rstrip("\n")
                    if line:
                        print(line)
                        if on_output:
                            on_output(line)
                        if "[+]" in line:
                            url_match = re.search(r"https?://[^\s]+", line)
                            if url_match:
                                platform_match = re.search(r"\[\+\]\s+(\S+):", line)
                                results["sherlock_profiles"].append({
                                    "platform": platform_match.group(1) if platform_match else "Unknown",
                                    "url": url_match.group(0),
                                })
                proc.wait()
                if os.path.exists(json_file):
                    _merge_sherlock_json(json_file, results["sherlock_profiles"])
            except FileNotFoundError:
                print("[!] Sherlock executable not found")
        else:
            print("[!] Sherlock not found on PATH or in venv Scripts dir")
            print("[*] Install: pip install sherlock-project")

        print(f"\n[+] Sherlock: found on {len(results['sherlock_profiles'])} platform(s)")
        _tick()

    # ------------------------------------------------------------------
    # 2. GitHub
    # ------------------------------------------------------------------
    if check_github and not (is_cancelled and is_cancelled()):
        print("\n--- GitHub ---")
        resp = _get(f"https://api.github.com/users/{username}")
        if resp and resp.status_code == 200:
            gh = resp.json()
            results["github"] = {
                "found": True,
                "login": gh.get("login"),
                "name": gh.get("name"),
                "bio": gh.get("bio"),
                "company": gh.get("company"),
                "location": gh.get("location"),
                "public_repos": gh.get("public_repos"),
                "followers": gh.get("followers"),
                "following": gh.get("following"),
                "created_at": gh.get("created_at"),
                "url": gh.get("html_url"),
            }
            print(f"[+] GitHub profile: {gh.get('html_url')}")
            print(f"    Name:     {gh.get('name') or 'N/A'}")
            print(f"    Repos:    {gh.get('public_repos')}")
            print(f"    Followers:{gh.get('followers')}")
            if gh.get("bio"):
                print(f"    Bio:      {gh.get('bio')[:100]}")
            if gh.get("company"):
                print(f"    Company:  {gh.get('company')}")
            if gh.get("location"):
                print(f"    Location: {gh.get('location')}")
        elif resp and resp.status_code == 404:
            results["github"] = {"found": False}
            print("[-] No GitHub profile found")
        else:
            results["github"] = {"found": False}
            print("[-] GitHub check failed or rate-limited")
        _tick()

    # ------------------------------------------------------------------
    # 3. Keybase
    # ------------------------------------------------------------------
    if check_keybase and not (is_cancelled and is_cancelled()):
        print("\n--- Keybase ---")
        resp = _get(f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}")
        if resp and resp.status_code == 200:
            try:
                kb_data = resp.json()
                them = kb_data.get("them", [])
                if them and them[0]:
                    profile = them[0]
                    basics = profile.get("basics", {})
                    proofs = profile.get("proofs_summary", {}).get("all", [])
                    results["keybase"] = {
                        "found": True,
                        "username": basics.get("username"),
                        "full_name": basics.get("display_name"),
                        "url": f"https://keybase.io/{username}",
                        "proofs": [
                            {"service": p.get("proof_type"), "handle": p.get("nametag")}
                            for p in proofs
                        ],
                    }
                    print(f"[+] Keybase profile: https://keybase.io/{username}")
                    if basics.get("display_name"):
                        print(f"    Display name: {basics.get('display_name')}")
                    if proofs:
                        print(f"    Linked accounts ({len(proofs)}):")
                        for p in proofs[:8]:
                            print(f"      [{p.get('proof_type')}] {p.get('nametag')}")
                else:
                    results["keybase"] = {"found": False}
                    print("[-] No Keybase profile found")
            except Exception:
                results["keybase"] = {"found": False}
                print("[-] Keybase parse error")
        else:
            results["keybase"] = {"found": False}
            print("[-] Keybase check failed")
        _tick()

    # ------------------------------------------------------------------
    # 4. HackerNews
    # ------------------------------------------------------------------
    if check_hackernews and not (is_cancelled and is_cancelled()):
        print("\n--- HackerNews ---")
        resp = _get(f"https://hacker-news.firebaseio.com/v0/user/{username}.json")
        if resp and resp.status_code == 200 and resp.text and resp.text.strip() != "null":
            try:
                hn = resp.json()
                if hn and hn.get("id"):
                    results["hackernews"] = {
                        "found": True,
                        "username": hn.get("id"),
                        "karma": hn.get("karma", 0),
                        "created": hn.get("created"),
                        "url": f"https://news.ycombinator.com/user?id={username}",
                    }
                    print(f"[+] HackerNews account: https://news.ycombinator.com/user?id={username}")
                    print(f"    Karma: {hn.get('karma', 0)}")
                else:
                    results["hackernews"] = {"found": False}
                    print("[-] No HackerNews account found")
            except Exception:
                results["hackernews"] = {"found": False}
                print("[-] HackerNews parse error")
        else:
            results["hackernews"] = {"found": False}
            print("[-] No HackerNews account found")
        _tick()

    # ------------------------------------------------------------------
    # 5. npm
    # ------------------------------------------------------------------
    if check_npm and not (is_cancelled and is_cancelled()):
        print("\n--- npm ---")
        resp = _get(f"https://registry.npmjs.org/-/v1/search?text=maintainer:{username}&size=5")
        if resp and resp.status_code == 200:
            try:
                npm_data = resp.json()
                total = npm_data.get("total", 0)
                packages = [
                    obj.get("package", {}).get("name")
                    for obj in npm_data.get("objects", [])
                ]
                if total > 0:
                    results["npm"] = {
                        "found": True,
                        "total_packages": total,
                        "packages": packages,
                        "url": f"https://www.npmjs.com/~{username}",
                    }
                    print(f"[+] npm maintainer found: {total} package(s)")
                    for p in packages:
                        print(f"    - {p}")
                else:
                    results["npm"] = {"found": False}
                    print("[-] No npm packages found for this username")
            except Exception:
                results["npm"] = {"found": False}
                print("[-] npm check failed")
        else:
            results["npm"] = {"found": False}
            print("[-] npm check failed")
        _tick()

    # ------------------------------------------------------------------
    # 6. PyPI
    # ------------------------------------------------------------------
    if check_pypi and not (is_cancelled and is_cancelled()):
        print("\n--- PyPI ---")
        resp = _get(f"https://pypi.org/user/{username}/")
        if resp and resp.status_code == 200:
            results["pypi"] = {
                "found": True,
                "url": f"https://pypi.org/user/{username}/",
            }
            print(f"[+] PyPI profile found: https://pypi.org/user/{username}/")
        else:
            results["pypi"] = {"found": False}
            print("[-] No PyPI profile found")
        _tick()

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"[*] Username OSINT Plus complete for: {username}")
    found_on = []
    if results["sherlock_profiles"]:
        found_on.append(f"Sherlock ({len(results['sherlock_profiles'])} sites)")
    if results.get("github", {}).get("found"):
        found_on.append("GitHub")
    if results.get("keybase", {}).get("found"):
        found_on.append("Keybase")
    if results.get("hackernews", {}).get("found"):
        found_on.append("HackerNews")
    if results.get("npm", {}).get("found"):
        found_on.append("npm")
    if results.get("pypi", {}).get("found"):
        found_on.append("PyPI")

    if found_on:
        print(f"[+] Found on: {', '.join(found_on)}")
    else:
        print("[-] No presence found on checked platforms")
    print("=" * 60)

    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _merge_sherlock_json(json_file: str, profiles: List[Dict]) -> None:
    """Merge Sherlock JSON output into profiles list (avoids duplicates)."""
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        existing_urls = {p.get("url") for p in profiles}
        for platform, info in data.items():
            if not isinstance(info, dict):
                continue
            url = info.get("url_user") or info.get("url")
            if url and url not in existing_urls:
                profiles.append({"platform": platform, "url": url})
                existing_urls.add(url)
    except Exception:
        pass


def _resolve_sherlock_command() -> Optional[List[str]]:
    """Resolve sherlock CLI from the active Python environment."""
    if os.name == "nt":
        script_dir = os.path.join(os.path.dirname(sys.executable), "Scripts")
        candidates = [
            os.path.join(script_dir, "sherlock.exe"),
            os.path.join(script_dir, "sherlock.cmd"),
            os.path.join(script_dir, "sherlock.bat"),
            os.path.join(script_dir, "sherlock"),
        ]
    else:
        script_dir = os.path.dirname(sys.executable)
        candidates = [os.path.join(script_dir, "sherlock")]

    for c in candidates:
        if os.path.exists(c):
            return [c]

    resolved = shutil.which("sherlock")
    if resolved:
        return [resolved]

    try:
        subprocess.run(
            [sys.executable, "-m", "sherlock", "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        return [sys.executable, "-m", "sherlock"]
    except (subprocess.TimeoutExpired, OSError):
        return None
