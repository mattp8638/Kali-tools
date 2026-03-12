"""
Report Window
Thin QMainWindow wrapper around the ReportPanel so Reporting can be
launched as a standalone window from the Hub (or via --phase reporting).
"""
import os
import sys

from PyQt5.QtWidgets import QMainWindow, QWidget
from PyQt5.QtCore import Qt

# Make sure exploit_host is importable
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EXPLOIT = os.path.join(_ROOT, "Exploitation")
if _EXPLOIT not in sys.path:
    sys.path.insert(0, _EXPLOIT)

from exploit_host.ui.report_panel import ReportPanel
from exploit_host.ui.theme import DARK_STYLESHEET


class ReportWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Kali Tools — Report Generator")
        self.setMinimumSize(1100, 750)
        self.resize(1280, 820)
        self.setStyleSheet(DARK_STYLESHEET)

        panel = ReportPanel(self)
        self.setCentralWidget(panel)
