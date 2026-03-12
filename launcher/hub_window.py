"""
Hub Window — Kali Tools Suite
The top-level launcher GUI.  Displays a phase card for every module,
a system dependency checker, and a recent activity log.
Opens each phase in its own independent QMainWindow (non-modal),
so all phases can run side-by-side.
"""
import os
import sys
import importlib
import subprocess
from typing import Dict, Optional

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QGroupBox, QGridLayout, QTextEdit,
    QStatusBar, QFrame, QProgressBar, QSizePolicy,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QColor


# ---------------------------------------------------------------------------
# Stylesheet (dark, no phase accent — neutral grey/white)
# ---------------------------------------------------------------------------
HUB_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0d0d0d;
    color: #e0e0e0;
    font-family: 'Segoe UI', 'Consolas', monospace;
    font-size: 13px;
}
QMenuBar { background-color: #111; color: #e0e0e0; border-bottom: 1px solid #333; }
QMenuBar::item:selected { background-color: #333; }
QMenu { background-color: #111; color: #e0e0e0; border: 1px solid #333; }
QMenu::item:selected { background-color: #333; }
QPushButton {
    background-color: #1e1e1e; color: #e0e0e0;
    border: 1px solid #444; border-radius: 6px;
    padding: 10px 18px; font-weight: bold;
}
QPushButton:hover  { background-color: #2a2a2a; border-color: #888; }
QPushButton:pressed{ background-color: #111; }
QPushButton:disabled{ color:#555; border-color:#222; }
QGroupBox {
    border: 1px solid #333; border-radius: 6px;
    margin-top: 14px; padding-top: 18px;
    font-weight: bold; color: #aaa;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
QTextEdit {
    background-color: #0a0a0a; color: #c0c0c0;
    border: 1px solid #333; border-radius: 4px;
    font-family: 'Consolas', monospace; font-size: 12px;
    padding: 6px;
}
QStatusBar { background-color: #111; color: #808fa0; border-top: 1px solid #333; }
QProgressBar {
    background-color: #111; border: 1px solid #333;
    border-radius: 4px; text-align: center; height: 8px;
}
QProgressBar::chunk { background-color: #555; border-radius: 3px; }
"""


# ---------------------------------------------------------------------------
# Phase definitions — colour, icon, description, key
# ---------------------------------------------------------------------------
PHASE_DEFS = [
    {
        "key":         "recon",
        "label":       "Reconnaissance",
        "icon":        "\U0001f50d",
        "accent":      "#00aaff",
        "desc":        "OSINT, DNS, subdomain enum,\nWHOIS, port sweep, web crawl",
    },
    {
        "key":         "scanning",
        "label":       "Scanning",
        "icon":        "\U0001f4e1",
        "accent":      "#00cc66",
        "desc":        "Nmap, service detection,\nbanner grab, OS fingerprint",
    },
    {
        "key":         "va",
        "label":       "Vulnerability Assessment",
        "icon":        "\U0001f9ea",
        "accent":      "#ffaa00",
        "desc":        "CVE lookup, Nikto, SSL/TLS,\nMisconfig checks, scoring",
    },
    {
        "key":         "exploitation",
        "label":       "Exploitation",
        "icon":        "\U0001f480",
        "accent":      "#ff3300",
        "desc":        "Web, auth, network, post-access\npayloads, C2, persistence",
    },
    {
        "key":         "reporting",
        "label":       "Reporting",
        "icon":        "\U0001f4cb",
        "accent":      "#cc88ff",
        "desc":        "Import TXT/JSON tool output,\nHTML / PDF / TXT report gen",
    },
]

# Packages to check on startup
DEP_CHECKS = [
    ("PyQt5",      "PyQt5",      True),
    ("yaml",       "pyyaml",     True),
    ("requests",   "requests",   True),
    ("reportlab",  "reportlab",  False),
    ("scapy",      "scapy",      False),
    ("paramiko",   "paramiko",   False),
    ("colorama",   "colorama",   False),
]


# ---------------------------------------------------------------------------
# Background dependency checker thread
# ---------------------------------------------------------------------------
class DepChecker(QThread):
    result = pyqtSignal(str, bool, bool)  # (import_name, installed, required)

    def run(self):
        for import_name, _, required in DEP_CHECKS:
            try:
                importlib.import_module(import_name)
                ok = True
            except ImportError:
                ok = False
            self.result.emit(import_name, ok, required)


# ---------------------------------------------------------------------------
# Phase Card widget
# ---------------------------------------------------------------------------
class PhaseCard(QFrame):
    launched = pyqtSignal(str)    # emits phase key

    def __init__(self, defn: dict, parent=None):
        super().__init__(parent)
        self._key    = defn["key"]
        self._accent = defn["accent"]
        self._active_window = None

        self.setFrameShape(QFrame.StyledPanel)
        self.setFixedSize(220, 190)
        self.setStyleSheet(
            f"PhaseCard {{ background:#111; border:2px solid #333; border-radius:10px; }}"
            f"PhaseCard:hover {{ border-color:{self._accent}; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(6)

        icon_lbl = QLabel(defn["icon"])
        icon_lbl.setStyleSheet("font-size:36px;")
        icon_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon_lbl)

        title = QLabel(defn["label"])
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            f"font-size:14px;font-weight:bold;color:{self._accent};"
        )
        title.setWordWrap(True)
        layout.addWidget(title)

        desc = QLabel(defn["desc"])
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet("font-size:11px;color:#888;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        layout.addStretch()

        self._btn = QPushButton("Launch")
        self._btn.setStyleSheet(
            f"background:{self._accent};color:#fff;border:none;"
            f"border-radius:5px;padding:6px 0;font-weight:bold;"
        )
        self._btn.clicked.connect(self._launch)
        layout.addWidget(self._btn)

    def _launch(self):
        # If already open, just raise it
        if self._active_window and self._active_window.isVisible():
            self._active_window.raise_()
            self._active_window.activateWindow()
            return
        self.launched.emit(self._key)

    def set_window(self, win):
        self._active_window = win

    def set_status(self, running: bool):
        self._btn.setText("Focus" if running else "Launch")


# ---------------------------------------------------------------------------
# Hub Window
# ---------------------------------------------------------------------------
class HubWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kali Tools Suite")
        self.setMinimumSize(1100, 680)
        self.resize(1200, 720)
        self.setStyleSheet(HUB_STYLESHEET)

        self._open_windows: Dict[str, QMainWindow] = {}
        self._cards: Dict[str, PhaseCard] = {}

        self._setup_ui()
        self._run_dep_check()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())

        body = QHBoxLayout()
        body.setContentsMargins(20, 20, 20, 20)
        body.setSpacing(20)

        # Left: phase cards
        left = QVBoxLayout()
        left.setSpacing(16)
        left.addWidget(self._build_phase_grid())
        left.addWidget(self._build_workflow_guide())
        left.addStretch()
        body.addLayout(left, 3)

        # Right: system check + activity log
        right = QVBoxLayout()
        right.setSpacing(16)
        right.addWidget(self._build_dep_panel())
        right.addWidget(self._build_log_panel())
        body.addLayout(right, 1)

        wrapper = QWidget()
        wrapper.setLayout(body)
        root.addWidget(wrapper, 1)

        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)
        self._statusbar.showMessage("Ready — select a phase to begin")

    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setStyleSheet(
            "background: qlineargradient("
            "x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #0a0a0a, stop:0.5 #111, stop:1 #0a0a0a);"
            "border-bottom: 1px solid #333;"
        )
        header.setFixedHeight(70)
        layout = QHBoxLayout(header)
        layout.setContentsMargins(24, 0, 24, 0)

        skull = QLabel("\U0001f4bb")
        skull.setStyleSheet("font-size:32px;")
        layout.addWidget(skull)

        title = QLabel("Kali Tools Suite")
        title.setStyleSheet(
            "font-size:24px;font-weight:bold;color:#e0e0e0;"
            "font-family:'Consolas',monospace;letter-spacing:2px;"
        )
        layout.addWidget(title)

        sub = QLabel("  Pentest Workflow Platform")
        sub.setStyleSheet("font-size:13px;color:#555;")
        layout.addWidget(sub)
        layout.addStretch()

        ver = QLabel("v1.0.0")
        ver.setStyleSheet("font-size:11px;color:#444;")
        layout.addWidget(ver)
        return header

    def _build_phase_grid(self) -> QGroupBox:
        grp = QGroupBox("Phases  —  click to launch each module")
        grid = QHBoxLayout(grp)
        grid.setSpacing(12)
        grid.setContentsMargins(12, 16, 12, 16)

        for defn in PHASE_DEFS:
            card = PhaseCard(defn)
            card.launched.connect(self._on_launch)
            self._cards[defn["key"]] = card
            grid.addWidget(card)

        return grp

    def _build_workflow_guide(self) -> QGroupBox:
        grp = QGroupBox("Typical Workflow")
        layout = QHBoxLayout(grp)
        layout.setContentsMargins(16, 16, 16, 12)
        layout.setSpacing(4)

        steps = [
            ("1", "Recon",   "#00aaff"),
            ("➡", "",       "#444"),
            ("2", "Scan",    "#00cc66"),
            ("➡", "",       "#444"),
            ("3", "Assess",  "#ffaa00"),
            ("➡", "",       "#444"),
            ("4", "Exploit", "#ff3300"),
            ("➡", "",       "#444"),
            ("5", "Report",  "#cc88ff"),
        ]
        for num, label, colour in steps:
            if num == "➡":
                arr = QLabel("➡")
                arr.setStyleSheet("color:#333;font-size:18px;")
                layout.addWidget(arr)
            else:
                box = QVBoxLayout()
                n = QLabel(num)
                n.setAlignment(Qt.AlignCenter)
                n.setStyleSheet(
                    f"background:{colour};color:#fff;font-weight:bold;"
                    f"border-radius:14px;padding:4px 10px;font-size:13px;"
                )
                l = QLabel(label)
                l.setAlignment(Qt.AlignCenter)
                l.setStyleSheet(f"color:{colour};font-size:11px;font-weight:bold;")
                box.addWidget(n)
                box.addWidget(l)
                layout.addLayout(box)

        layout.addStretch()
        return grp

    def _build_dep_panel(self) -> QGroupBox:
        grp = QGroupBox("System Check")
        self._dep_layout = QVBoxLayout(grp)
        self._dep_layout.setSpacing(4)
        self._dep_layout.setContentsMargins(12, 16, 12, 12)

        self._dep_rows: Dict[str, QLabel] = {}
        for import_name, pkg_name, required in DEP_CHECKS:
            row = QHBoxLayout()
            name_lbl = QLabel(f"{pkg_name}{'*' if required else ''}")
            name_lbl.setFixedWidth(110)
            name_lbl.setStyleSheet("color:#aaa;font-size:11px;")
            status_lbl = QLabel("checking...")
            status_lbl.setStyleSheet("color:#555;font-size:11px;")
            row.addWidget(name_lbl)
            row.addWidget(status_lbl)
            row.addStretch()
            self._dep_rows[import_name] = status_lbl
            self._dep_layout.addLayout(row)

        note = QLabel("* required  │  others: optional")
        note.setStyleSheet("color:#444;font-size:10px;margin-top:6px;")
        self._dep_layout.addWidget(note)
        return grp

    def _build_log_panel(self) -> QGroupBox:
        grp = QGroupBox("Activity")
        layout = QVBoxLayout(grp)
        layout.setContentsMargins(8, 12, 8, 8)
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMinimumHeight(160)
        layout.addWidget(self._log)
        return grp

    # ------------------------------------------------------------------
    # Dependency check
    # ------------------------------------------------------------------

    def _run_dep_check(self):
        self._dep_thread = DepChecker()
        self._dep_thread.result.connect(self._on_dep_result)
        self._dep_thread.start()

    def _on_dep_result(self, import_name: str, installed: bool, required: bool):
        lbl = self._dep_rows.get(import_name)
        if not lbl:
            return
        if installed:
            lbl.setText("\u2705 installed")
            lbl.setStyleSheet("color:#00cc66;font-size:11px;")
        else:
            if required:
                lbl.setText("\u274c missing (required)")
                lbl.setStyleSheet("color:#ff3300;font-size:11px;font-weight:bold;")
            else:
                lbl.setText("\u26a0 not installed")
                lbl.setStyleSheet("color:#ffaa00;font-size:11px;")

    # ------------------------------------------------------------------
    # Phase launching
    # ------------------------------------------------------------------

    def _on_launch(self, phase_key: str):
        # If already open, just focus it
        existing = self._open_windows.get(phase_key)
        if existing and existing.isVisible():
            existing.raise_()
            existing.activateWindow()
            return

        self._log_line(f"[*] Launching {phase_key}...")
        self._statusbar.showMessage(f"Opening {phase_key}...")

        try:
            from launcher.phase_launcher import launch_phase
            window = launch_phase(phase_key)
            window.setAttribute(Qt.WA_DeleteOnClose)
            window.destroyed.connect(lambda: self._on_phase_closed(phase_key))
            window.show()

            self._open_windows[phase_key] = window
            self._cards[phase_key].set_window(window)
            self._cards[phase_key].set_status(True)
            self._log_line(f"[+] {phase_key} opened")
            self._statusbar.showMessage(f"{phase_key} running")

        except Exception as e:
            self._log_line(f"[!] Failed to launch {phase_key}: {e}")
            self._statusbar.showMessage(f"Error: {e}")

    def _on_phase_closed(self, phase_key: str):
        self._open_windows.pop(phase_key, None)
        if phase_key in self._cards:
            self._cards[phase_key].set_status(False)
        self._log_line(f"[~] {phase_key} closed")

    def _log_line(self, msg: str):
        self._log.append(msg)
        sb = self._log.verticalScrollBar()
        sb.setValue(sb.maximum())

    def closeEvent(self, event):
        # Close all child phase windows gracefully
        for win in list(self._open_windows.values()):
            try:
                win.close()
            except Exception:
                pass
        event.accept()
