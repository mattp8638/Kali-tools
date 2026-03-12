#!/usr/bin/env python3
"""
Scanning App Host - Main entry point.
Standalone PyQt5 application for running scanning tools.
"""
import os
import sys

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication

from scanning_host.core.registry import ToolRegistry
from scanning_host.ui.main_window import MainWindow


def main() -> int:
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("Scanning App Host")
    app.setOrganizationName("KaliScanning")

    plugins_dir = os.path.join(os.path.dirname(__file__), "scanning_host", "plugins")
    registry = ToolRegistry(plugins_dir=plugins_dir)
    count = registry.discover_tools()
    print(f"[*] Discovered {count} scanning tool(s)")

    window = MainWindow(registry)
    window.show()

    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
