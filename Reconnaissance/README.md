# Kali App Host

A Windows PyQt5 desktop application for hosting and running Kali Python reconnaissance tools. Each tool is a self-contained Python module with a YAML definition, making it easy to add new tools as plugins.

## Architecture

```
kali-app-host/
├── main.py                      # Entry point
├── requirements.txt             # Python dependencies
├── kali_host/
│   ├── __init__.py
│   ├── core/
│   │   ├── models.py            # Data models (ToolDefinition, ScanResult, Project)
│   │   ├── registry.py          # Plugin discovery and tool registry
│   │   └── runner.py            # Background thread execution with output capture
│   ├── ui/
│   │   ├── theme.py             # Dark Kali-inspired stylesheet
│   │   ├── param_form.py        # Dynamic parameter form builder
│   │   ├── output_panel.py      # Console output + structured results viewer
│   │   └── main_window.py       # Main application window
│   ├── tools/                   # Python tool modules
│   │   ├── ping_sweep.py        # ICMP host discovery
│   │   ├── port_scanner.py      # TCP port scanner with banner grab
│   │   ├── dns_recon.py         # DNS record enumeration
│   │   ├── whois_lookup.py      # WHOIS registration lookup
│   │   ├── http_headers.py      # HTTP header security analysis
│   │   └── subdomain_enum.py    # Subdomain discovery (DNS + CT logs)
│   └── plugins/                 # YAML tool definitions
│       ├── ping_sweep.yaml
│       ├── port_scanner.yaml
│       ├── dns_recon.yaml
│       ├── whois_lookup.yaml
│       ├── http_headers.yaml
│       └── subdomain_enum.yaml
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python main.py
```

## How It Works

1. **Tool Registry** scans `kali_host/plugins/*.yaml` on startup to discover available tools
2. **Sidebar** shows tools grouped by category (Network Discovery, Port Scanning, DNS Recon, etc.)
3. **Parameter Form** dynamically generates input fields from the YAML definition
4. **Runner** executes the tool's Python module in a background QThread
5. **Output Panel** streams stdout in real-time with colour-coded lines, then shows structured results in a tree view
6. **Projects** group scan results and can be saved/loaded as JSON files

## Adding a New Tool

### 1. Create the Python module

Create `kali_host/tools/my_tool.py`:

```python
def run(params, on_progress=None, on_output=None, is_cancelled=None):
    target = params.get("target", "")
    print(f"[*] Running my tool on {target}")
    # ... do work, print output ...
    return {"target": target, "findings": [...]}
```

The `run` function signature:
- `params: Dict[str, Any]` — user-provided parameters
- `on_progress(current, total)` — progress callback
- `on_output(line)` — direct output callback (bypasses stdout capture)
- `is_cancelled() -> bool` — check if user cancelled

### 2. Create the YAML definition

Create `kali_host/plugins/my_tool.yaml`:

```yaml
tool_id: my_tool
name: My Custom Tool
description: "What this tool does"
category: Custom           # Network Discovery | Port Scanning | DNS Recon | Web Recon | OSINT | Vulnerability | Custom
module_path: kali_host.tools.my_tool
entry_function: run
version: "1.0.0"
tags: [recon, custom]

params:
  - name: target
    label: "Target"
    param_type: string     # string | integer | boolean | choice | ip_address | ip_range | domain | port_range | file_path
    required: true
    placeholder: "Enter target"
    help_text: "The target to scan"
```

### 3. Reload

Press **F5** in the app or restart. The new tool appears in the sidebar.

## Tool Interface

Every tool module must export a `run()` function with this signature:

```python
def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
```

**Output conventions:**
- `[*]` Info lines (cyan)
- `[+]` Positive findings (green)
- `[-]` Negative/no result (grey)
- `[!]` Warnings (red)
- `[ERROR]` Errors (bright red)

## Packaging for Distribution

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "KaliAppHost" --add-data "kali_host/plugins;kali_host/plugins" main.py
```

The resulting `dist/KaliAppHost.exe` is a standalone Windows executable.

## Dependencies

- **PyQt5** — GUI framework
- **PyYAML** — Plugin definition parsing
- **dnspython** — DNS resolution (optional, falls back to system tools)
- **python-whois** — WHOIS lookups (optional, falls back to system tools)
