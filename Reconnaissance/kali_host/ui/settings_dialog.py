"""
Settings Dialog — manage API keys for all supported reconnaissance services.
"""
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QScrollArea, QWidget,
    QDialogButtonBox, QFrame, QMessageBox, QToolButton,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from ..core.api_keys import get_api_key_manager


class APIKeyRow(QWidget):
    """A single row: service label + key input + show/hide toggle + clear button."""

    def __init__(self, service_id: str, description: str, current_value: str = "", parent=None):
        super().__init__(parent)
        self._service_id = service_id

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(8)

        # Service name label
        name_label = QLabel(service_id)
        name_label.setFixedWidth(140)
        name_label.setFont(QFont("Consolas", 9))
        name_label.setStyleSheet("color: #00d4ff;")
        name_label.setToolTip(description)
        layout.addWidget(name_label)

        # Description label
        desc_label = QLabel(description.split(" - ", 1)[-1] if " - " in description else description)
        desc_label.setStyleSheet("color: #6b7a8d; font-size: 11px;")
        desc_label.setFixedWidth(240)
        desc_label.setToolTip(description)
        layout.addWidget(desc_label)

        # Key input
        self._key_input = QLineEdit()
        self._key_input.setPlaceholderText("Enter API key...")
        self._key_input.setEchoMode(QLineEdit.Password)
        self._key_input.setText(current_value)
        self._key_input.setMinimumWidth(300)
        self._key_input.setStyleSheet("""
            background-color: #0d1117;
            border: 1px solid #30363d;
            color: #e6edf3;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: Consolas, monospace;
        """)
        layout.addWidget(self._key_input, 1)

        # Show / hide toggle
        self._toggle_btn = QToolButton()
        self._toggle_btn.setText("👁")
        self._toggle_btn.setCheckable(True)
        self._toggle_btn.setToolTip("Show / hide key")
        self._toggle_btn.setStyleSheet("""
            QToolButton { border: none; color: #6b7a8d; font-size: 14px; padding: 2px 4px; }
            QToolButton:hover { color: #00d4ff; }
            QToolButton:checked { color: #00d4ff; }
        """)
        self._toggle_btn.toggled.connect(self._toggle_visibility)
        layout.addWidget(self._toggle_btn)

        # Clear button
        clear_btn = QToolButton()
        clear_btn.setText("✕")
        clear_btn.setToolTip(f"Clear {service_id} key")
        clear_btn.setStyleSheet("""
            QToolButton { border: none; color: #6b7a8d; font-size: 12px; padding: 2px 4px; }
            QToolButton:hover { color: #ff4757; }
        """)
        clear_btn.clicked.connect(self._clear_key)
        layout.addWidget(clear_btn)

    def _toggle_visibility(self, checked: bool):
        if checked:
            self._key_input.setEchoMode(QLineEdit.Normal)
        else:
            self._key_input.setEchoMode(QLineEdit.Password)

    def _clear_key(self):
        self._key_input.clear()

    @property
    def service_id(self) -> str:
        return self._service_id

    @property
    def key_value(self) -> str:
        return self._key_input.text().strip()


class SettingsDialog(QDialog):
    """Settings dialog for managing API keys."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._manager = get_api_key_manager()
        self._rows: list[APIKeyRow] = []

        self.setWindowTitle("Settings — API Keys")
        self.setMinimumWidth(820)
        self.setMinimumHeight(520)
        self.resize(900, 600)
        self.setModal(True)

        # Inherit the app dark stylesheet from parent if set
        if parent:
            self.setStyleSheet(parent.styleSheet())

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 12)

        # Header
        header = QLabel("API Keys")
        header.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #00d4ff;
            font-family: Consolas, monospace;
            padding-bottom: 4px;
        """)
        layout.addWidget(header)

        subtitle = QLabel(
            "Keys are stored locally in <code>~/.kali_tools/api_keys.json</code>. "
            "They are never transmitted except to the respective service."
        )
        subtitle.setStyleSheet("color: #6b7a8d; font-size: 12px;")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        # Divider
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #30363d;")
        layout.addWidget(line)

        # Column headers
        col_header = QWidget()
        col_layout = QHBoxLayout(col_header)
        col_layout.setContentsMargins(0, 0, 0, 0)
        col_layout.setSpacing(8)
        for text, width in [("Service", 140), ("Description", 240), ("API Key", None)]:
            lbl = QLabel(text)
            lbl.setStyleSheet("color: #6b7a8d; font-size: 11px; font-weight: bold;")
            if width:
                lbl.setFixedWidth(width)
            else:
                lbl.setMinimumWidth(300)
            col_layout.addWidget(lbl, 0 if width else 1)
        # Padding for toggle + clear buttons
        col_layout.addWidget(QLabel(""), 0)
        layout.addWidget(col_header)

        # Scrollable key rows
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background-color: transparent;")

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(0, 0, 8, 0)
        scroll_layout.setSpacing(0)

        existing_keys = self._manager.get_all_keys()
        services = self._manager.get_supported_services()

        for service_id, description in services.items():
            current = existing_keys.get(service_id, "")
            row = APIKeyRow(service_id, description, current, scroll_content)

            # Alternate row background
            if len(self._rows) % 2 == 0:
                row.setStyleSheet("background-color: rgba(255,255,255,0.02); border-radius: 3px;")

            scroll_layout.addWidget(row)
            self._rows.append(row)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll, 1)

        # Divider
        line2 = QFrame()
        line2.setFrameShape(QFrame.HLine)
        line2.setStyleSheet("color: #30363d;")
        layout.addWidget(line2)

        # Buttons
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.button(QDialogButtonBox.Ok).setText("Save Keys")
        btn_box.button(QDialogButtonBox.Ok).setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: #ffffff;
                border: none;
                padding: 6px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #2ea043; }
        """)
        btn_box.button(QDialogButtonBox.Cancel).setStyleSheet("""
            QPushButton {
                background-color: #21262d;
                color: #e6edf3;
                border: 1px solid #30363d;
                padding: 6px 20px;
                border-radius: 4px;
            }
            QPushButton:hover { background-color: #30363d; }
        """)
        btn_box.accepted.connect(self._save_keys)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def _save_keys(self):
        """Persist all non-empty keys; remove blanked-out ones."""
        saved = 0
        removed = 0

        for row in self._rows:
            value = row.key_value
            if value:
                self._manager.set_key(row.service_id, value)
                saved += 1
            elif self._manager.has_key(row.service_id):
                # User cleared a previously set key
                self._manager.remove_key(row.service_id)
                removed += 1

        parts = []
        if saved:
            parts.append(f"{saved} key(s) saved")
        if removed:
            parts.append(f"{removed} key(s) removed")
        if not parts:
            parts.append("No changes")

        self.accept()

        # Show result in parent status bar if available
        if self.parent() and hasattr(self.parent(), "_statusbar"):
            self.parent()._statusbar.showMessage(" | ".join(parts))
        else:
            QMessageBox.information(self, "Saved", " | ".join(parts) + ".")
