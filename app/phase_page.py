"""
Phase Page
One instance per phase. Embeds the existing per-phase MainWindow
inside a QWidget frame so it sits inside the unified app shell
rather than opening as a separate OS window.

Each phase’s MainWindow is instantiated lazily on first visit to
avoid importing all modules on startup.
"""
import os
import sys
import importlib

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QSizePolicy, QStackedWidget,
)
from PyQt5.QtCore import Qt, pyqtSignal

from .style import PHASE_ACCENTS

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PhasePage(QWidget):
    status_message = pyqtSignal(str)

    def __init__(self, phase_def: dict, parent=None):
        super().__init__(parent)
        self._def    = phase_def
        self._loaded = False
        self._inner  = None
        self._setup_placeholder()

    # ------------------------------------------------------------------
    # Placeholder shown before first load
    # ------------------------------------------------------------------
    def _setup_placeholder(self):
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self._layout.addWidget(self._make_header())

        self._body_stack = QStackedWidget()
        self._layout.addWidget(self._body_stack, 1)

        # Placeholder (shown until first click)
        ph = QWidget()
        ph_layout = QVBoxLayout(ph)
        ph_layout.setAlignment(Qt.AlignCenter)
        icon = QLabel(self._def["icon"])
        icon.setStyleSheet("font-size:64px;")
        icon.setAlignment(Qt.AlignCenter)
        msg = QLabel(f"Click to load {self._def['label']} tools")
        msg.setStyleSheet("color:#444;font-size:14px;")
        msg.setAlignment(Qt.AlignCenter)
        ph_layout.addWidget(icon)
        ph_layout.addWidget(msg)
        self._body_stack.addWidget(ph)
        self._placeholder = ph

    def _make_header(self) -> QWidget:
        accent = PHASE_ACCENTS.get(self._def["key"], "#888")
        hdr = QWidget()
        hdr.setObjectName("phaseHeader")
        hdr.setStyleSheet(
            f"background:#0d0d0d;"
            f"border-bottom:2px solid {accent};"
        )
        hdr.setFixedHeight(52)
        layout = QHBoxLayout(hdr)
        layout.setContentsMargins(16, 0, 16, 0)

        icon = QLabel(self._def["icon"])
        icon.setStyleSheet("font-size:22px;")
        layout.addWidget(icon)

        title = QLabel(self._def["label"])
        title.setObjectName("phaseTitle")
        title.setStyleSheet(f"font-size:18px;font-weight:bold;color:{accent};")
        layout.addWidget(title)

        sub = QLabel(self._def["subtitle"])
        sub.setObjectName("phaseSubtitle")
        layout.addWidget(sub)
        layout.addStretch()
        return hdr

    # ------------------------------------------------------------------
    # Lazy load — called the first time this page becomes visible
    # ------------------------------------------------------------------
    def showEvent(self, event):
        super().showEvent(event)
        if not self._loaded:
            self._load_phase()

    def _load_phase(self):
        ph = self._def
        key = ph["key"]

        # Reporting: embed ReportPanel directly
        if key == "reporting":
            self._load_report_panel()
            return

        # All other phases: instantiate their MainWindow as an embedded widget
        try:
            subdir = os.path.join(_ROOT, ph["subdir"])
            if subdir not in sys.path:
                sys.path.insert(0, subdir)

            # Import registry
            reg_parts  = ph["registry"].rsplit(".", 1)
            reg_mod    = importlib.import_module(reg_parts[0])
            RegistryCls = getattr(reg_mod, reg_parts[1])

            plugins_dir = os.path.join(_ROOT, ph["plugins"])
            registry    = RegistryCls(plugins_dir=plugins_dir)
            count       = registry.discover_tools()

            # Import MainWindow
            win_parts  = ph["registry"].rsplit(".", 2)  # e.g. kali_host.core.registry
            win_pkg    = win_parts[0].rsplit(".", 1)[0]  # e.g. kali_host
            win_module = importlib.import_module(f"{win_pkg}.ui.main_window")
            WindowCls  = getattr(win_module, "MainWindow")

            # Create it as an embedded widget (no setWindowFlags needed —
            # it will be reparented into our layout)
            inner = WindowCls(registry)
            # Remove the native window decoration and embed it
            inner.setWindowFlags(Qt.Widget)
            inner.setParent(self)
            inner.statusBar().hide()   # we use the outer status bar
            inner.menuBar().hide()     # we use our own nav

            self._body_stack.addWidget(inner)
            self._body_stack.setCurrentWidget(inner)
            self._inner = inner
            self._loaded = True
            self.status_message.emit(
                f"{ph['label']}: {count} tool(s) loaded"
            )
        except Exception as e:
            from PyQt5.QtWidgets import QLabel
            err = QLabel(f"\u26a0\ufe0f  Failed to load {ph['label']}:\n{e}")
            err.setStyleSheet("color:#ff6644;font-size:13px;padding:32px;")
            err.setAlignment(Qt.AlignCenter)
            err.setWordWrap(True)
            self._body_stack.addWidget(err)
            self._body_stack.setCurrentWidget(err)
            self._loaded = True

    def _load_report_panel(self):
        try:
            exploit_dir = os.path.join(_ROOT, "Exploitation")
            if exploit_dir not in sys.path:
                sys.path.insert(0, exploit_dir)
            from exploit_host.ui.report_panel import ReportPanel
            panel = ReportPanel(self)
            self._body_stack.addWidget(panel)
            self._body_stack.setCurrentWidget(panel)
            self._inner  = panel
            self._loaded = True
            self.status_message.emit("Reporting panel loaded")
        except Exception as e:
            from PyQt5.QtWidgets import QLabel
            err = QLabel(f"\u26a0\ufe0f  Reporting failed to load: {e}")
            err.setStyleSheet("color:#ff6644;font-size:13px;padding:32px;")
            self._body_stack.addWidget(err)
            self._body_stack.setCurrentWidget(err)
            self._loaded = True
