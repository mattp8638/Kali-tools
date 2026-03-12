"""
Phase Launcher
Instantiates the MainWindow for any given phase by dynamically importing
the correct module from each subfolder.
Called either by HubWindow phase-card buttons or by main.py --phase flag.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Phase descriptor table
# Each entry: (display_name, sys_path_subdir, module, plugins_subpath)
PHASES = {
    "recon": {
        "name":        "Reconnaissance",
        "subdir":      "Reconnaissance",
        "registry":    "kali_host.core.registry.ToolRegistry",
        "window":      "kali_host.ui.main_window.MainWindow",
        "plugins_rel": os.path.join("kali_host", "plugins"),
    },
    "scanning": {
        "name":        "Scanning",
        "subdir":      "Scanning",
        "registry":    "scanning_host.core.registry.ToolRegistry",
        "window":      "scanning_host.ui.main_window.MainWindow",
        "plugins_rel": os.path.join("scanning_host", "plugins"),
    },
    "va": {
        "name":        "Vulnerability Assessment",
        "subdir":      "Vulnerability Assessment",
        "registry":    "va_host.core.registry.ToolRegistry",
        "window":      "va_host.ui.main_window.MainWindow",
        "plugins_rel": os.path.join("va_host", "plugins"),
    },
    "exploitation": {
        "name":        "Exploitation",
        "subdir":      "Exploitation",
        "registry":    "exploit_host.core.registry.ToolRegistry",
        "window":      "exploit_host.ui.main_window.MainWindow",
        "plugins_rel": os.path.join("exploit_host", "plugins"),
    },
    "reporting": {
        "name":        "Reporting",
        "subdir":      "Exploitation",   # report panel lives here
        "registry":    None,              # no separate registry needed
        "window":      None,              # uses ReportWindow wrapper below
        "plugins_rel": None,
    },
}


def _ensure_path(subdir: str):
    """Add a phase subfolder to sys.path if not already present."""
    p = os.path.join(_ROOT, subdir)
    if p not in sys.path:
        sys.path.insert(0, p)


def _import_class(dotted_path: str):
    """Import and return a class from a dotted module path."""
    parts = dotted_path.rsplit(".", 1)
    import importlib
    mod = importlib.import_module(parts[0])
    return getattr(mod, parts[1])


def launch_phase(phase_key: str):
    """
    Instantiate and return (but don't show) the QMainWindow for phase_key.
    Raises KeyError for unknown phases.
    """
    if phase_key not in PHASES:
        raise KeyError(f"Unknown phase: {phase_key!r}")

    cfg = PHASES[phase_key]
    _ensure_path(cfg["subdir"])

    # ---- Reporting uses a standalone wrapper window ----
    if phase_key == "reporting":
        _ensure_path("Exploitation")
        from launcher.report_window import ReportWindow
        return ReportWindow()

    # ---- All other phases: registry + MainWindow ----
    RegistryCls = _import_class(cfg["registry"])
    WindowCls   = _import_class(cfg["window"])

    plugins_dir = os.path.join(_ROOT, cfg["subdir"], cfg["plugins_rel"])
    registry = RegistryCls(plugins_dir=plugins_dir)
    count = registry.discover_tools()
    print(f"[Launcher] {cfg['name']}: {count} tool(s) loaded")

    return WindowCls(registry)
