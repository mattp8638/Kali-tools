"""
Kali Tools Suite — Unified Main Window

Layout:
  ┌──────────────────────────────────────────────────────┐
  │  HEADER: Kali Tools Suite                           │
  ├────────────┬───────────────────────────────────────────┤
  │ SIDE NAV │  QStackedWidget (one page per phase)       │
  │  ⬢ Full  │   Each page:                               │
  │  🔍 Recon  │     Phase header banner (accent colour)   │
  │  📡 Scan   │     Splitter:                             │
  │  🧪 VA     │       Left: tool tree (categories)        │
  │  💀 Exploit│       Centre: param form + run/cancel     │
  │  📋 Report │       Right: output / results tabs         │
  ├────────────┴───────────────────────────────────────────┤
  │  STATUS BAR                                         │
  └──────────────────────────────────────────────────────┘
"""
import os
import sys

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QStackedWidget, QStatusBar,
    QSizePolicy, QFrame, QSplitter,
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

from .style import APP_STYLE, PHASE_ACCENTS
from .phase_page import PhasePage
from .full_pentest_page import FullPentestPage

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---- phase metadata ----
PHASES = [
    {
        "key":      "recon",
        "label":    "Reconnaissance",
        "icon":     "\U0001f50d",
        "subtitle": "OSINT • DNS • Subdomain enum • WHOIS • Crawl",
        "subdir":   "Reconnaissance",
        "pkg":      "kali_host",
        "registry": "kali_host.core.registry.ToolRegistry",
        "plugins":  os.path.join("Reconnaissance", "kali_host", "plugins"),
    },
    {
        "key":      "scanning",
        "label":    "Scanning",
        "icon":     "\U0001f4e1",
        "subtitle": "Nmap • Service detect • Banner grab • OS fingerprint",
        "subdir":   "Scanning",
        "pkg":      "scanning_host",
        "registry": "scanning_host.core.registry.ToolRegistry",
        "plugins":  os.path.join("Scanning", "scanning_host", "plugins"),
    },
    {
        "key":      "va",
        "label":    "Vulnerability Assessment",
        "icon":     "\U0001f9ea",
        "subtitle": "CVE lookup • Nikto • SSL/TLS • Misconfig scoring",
        "subdir":   "Vulnerability Assessment",
        "pkg":      "va_host",
        "registry": "va_host.core.registry.ToolRegistry",
        "plugins":  os.path.join("Vulnerability Assessment", "va_host", "plugins"),
    },
    {
        "key":      "exploitation",
        "label":    "Exploitation",
        "icon":     "\U0001f480",
        "subtitle": "Web • Auth • Network • Post-access • Payloads • C2",
        "subdir":   "Exploitation",
        "pkg":      "exploit_host",
        "registry": "exploit_host.core.registry.ToolRegistry",
        "plugins":  os.path.join("Exploitation", "exploit_host", "plugins"),
    },
    {
        "key":      "reporting",
        "label":    "Reporting",
        "icon":     "\U0001f4cb",
        "subtitle": "Import TXT/JSON • HTML • PDF • TXT • JSON reports",
        "subdir":   "Exploitation",  # ReportPanel lives in exploit_host
        "pkg":      None,
        "registry": None,
        "plugins":  None,
    },
]


class AppMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kali Tools Suite")
        self.setMinimumSize(1300, 800)
        self.resize(1500, 900)
        self.setStyleSheet(APP_STYLE)

        self._nav_btns: dict = {}
        self._active_key: str = None

        # Create status bar FIRST — _build_stack() connects signals to it
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("Ready")

        self._setup_ui()
        # Boot on Full Pentest page
        self._switch_to("fullpentest")

    # ------------------------------------------------------------------
    def _setup_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_header())

        # Create status bar early so pages can connect to it during stack build
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("Ready")

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_stack(), 1)

        body_w = QWidget()
        body_w.setLayout(body)
        outer.addWidget(body_w, 1)

        # status bar already created above

    def _build_header(self) -> QWidget:
        w = QWidget()
        w.setObjectName("appHeader")
        w.setFixedHeight(48)
        w.setStyleSheet(
            "background: #080808;"
            "border-bottom: 1px solid #1a1a1a;"
        )
        layout = QHBoxLayout(w)
        layout.setContentsMargins(18, 0, 18, 0)

        logo = QLabel("\U0001f4bb  Kali Tools Suite")
        logo.setStyleSheet(
            "font-size:18px;font-weight:bold;color:#ccc;"
            "font-family:'Consolas',monospace;letter-spacing:1px;"
        )
        layout.addWidget(logo)
        layout.addStretch()

        ver = QLabel("v1.0.0")
        ver.setStyleSheet("color:#333;font-size:11px;")
        layout.addWidget(ver)
        return w

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 12, 0, 12)
        layout.setSpacing(0)

        # ---- Section label ----
        sec = QLabel("PHASES")
        sec.setObjectName("sidebarTitle")
        layout.addWidget(sec)

        # ---- Full Pentest (gold) ----
        fp_btn = QPushButton("\u2b22  Full Pentest")
        fp_btn.setObjectName("fullPentestBtn")
        fp_btn.setCheckable(False)
        fp_btn.clicked.connect(lambda: self._switch_to("fullpentest"))
        fp_btn.setCursor(Qt.PointingHandCursor)
        layout.addWidget(fp_btn)
        self._nav_btns["fullpentest"] = fp_btn

        # ---- Divider ----
        div = QFrame()
        div.setFrameShape(QFrame.HLine)
        div.setStyleSheet("color:#1a1a1a;margin:6px 0;")
        layout.addWidget(div)

        # ---- Phase buttons ----
        for ph in PHASES:
            btn = QPushButton(f"{ph['icon']}  {ph['label']}")
            btn.setObjectName("navBtn")
            btn.setCheckable(False)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setProperty("active", "false")
            btn.clicked.connect(lambda checked, k=ph["key"]: self._switch_to(k))
            layout.addWidget(btn)
            self._nav_btns[ph["key"]] = btn

        layout.addStretch()

        # ---- Bottom: quit ----
        quit_btn = QPushButton("\u2715  Quit")
        quit_btn.setObjectName("navBtn")
        quit_btn.setCursor(Qt.PointingHandCursor)
        quit_btn.clicked.connect(self.close)
        layout.addWidget(quit_btn)
        return sidebar

    def _build_stack(self) -> QStackedWidget:
        self._stack = QStackedWidget()
        self._stack.setObjectName("contentStack")
        self._pages: dict = {}

        # Full Pentest page (index 0)
        fp_page = FullPentestPage(PHASES)
        fp_page.status_message.connect(self._status.showMessage)
        self._stack.addWidget(fp_page)
        self._pages["fullpentest"] = fp_page

        # One PhasePage per phase
        for ph in PHASES:
            page = PhasePage(ph)
            page.status_message.connect(self._status.showMessage)
            self._stack.addWidget(page)
            self._pages[ph["key"]] = page

        return self._stack

    # ------------------------------------------------------------------
    def _switch_to(self, key: str):
        if key not in self._pages:
            return
        # Update nav button states
        for k, btn in self._nav_btns.items():
            btn.setProperty("active", "true" if k == key else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
            if k == key and btn.objectName() == "navBtn":
                accent = PHASE_ACCENTS.get(key, "#888")
                btn.setStyleSheet(
                    f"QPushButton#navBtn {{ "
                    f"border-left: 3px solid {accent};"
                    f"color: #fff; background: #151515;"
                    f"font-weight: bold; "
                    f"text-align: left; padding: 10px 16px; border-radius: 0; }}"
                )
            elif btn.objectName() == "navBtn":
                btn.setStyleSheet("")

        self._stack.setCurrentWidget(self._pages[key])
        self._active_key = key
        label = "Full Pentest" if key == "fullpentest" else next(
            (p["label"] for p in PHASES if p["key"] == key), key
        )
        self._status.showMessage(f"Phase: {label}")
