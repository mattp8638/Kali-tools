import importlib
import json
import sys
import ast


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python run_tool.py <module_name> [json_params]")
        print("Example: python run_tool.py banner_grab '{\"target\":\"scanme.nmap.org\",\"ports\":\"22,80\"}'")
        return 1

    module_name = sys.argv[1]
    params = {}
    if len(sys.argv) > 2:
        raw = sys.argv[2]
        try:
            params = json.loads(raw)
        except json.JSONDecodeError:
            # PowerShell quoting often breaks strict JSON; allow Python dict literal as fallback.
            params = ast.literal_eval(raw)

    if "." not in module_name:
        module_name = f"scanning_host.tools.{module_name}"
    mod = importlib.import_module(module_name)
    out = mod.run(params)
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
