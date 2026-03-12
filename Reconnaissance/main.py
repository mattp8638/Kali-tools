#!/usr/bin/env python3
"""
Kali App Host - Main entry point.
A Windows PyQt5 application for hosting and running Kali Python recon tools.
"""
import sys
import os

# Add project root to path so tool modules can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

from kali_host.core.registry import ToolRegistry
from kali_host.ui.main_window import MainWindow


def main():
    # High DPI support
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("Kali App Host")
    app.setOrganizationName("KaliAppHost")

    # Discover tools
    plugins_dir = os.path.join(os.path.dirname(__file__), "kali_host", "plugins")
    registry = ToolRegistry(plugins_dir=plugins_dir)
    count = registry.discover_tools()
    print(f"[*] Discovered {count} tool(s)")

    # Launch main window
    window = MainWindow(registry)
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
