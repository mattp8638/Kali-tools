#!/usr/bin/env python3
"""
Kali Tools Suite — Unified Single-Window Application
One window. Left nav selects the phase. Content area shows that phase's tools.
The ⬢ Full Pentest option at the top of the nav runs all phases in sequence.

Usage:
    python main.py
"""
import sys
import os

_ROOT = os.path.dirname(os.path.abspath(__file__))
for _sub in ("Reconnaissance", "Scanning",
             "Vulnerability Assessment", "Exploitation", "Reporting"):
    _p = os.path.join(_ROOT, _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from app.main_window import AppMainWindow


def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    app.setApplicationName("Kali Tools Suite")
    window = AppMainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
