"""
Output Panel - Real-time tool output viewer with tabs for raw output and structured results.
"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QTextEdit, QPlainTextEdit, QTreeWidget, QTreeWidgetItem,
    QPushButton, QLabel, QFileDialog, QHeaderView,
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QTextCursor, QColor, QFont
from typing import Dict, Any, Optional
from datetime import datetime

from ..core.models import ScanResult, ToolStatus


class OutputPanel(QWidget):
    """Tabbed output viewer with raw console and structured results."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Tab widget
        self._tabs = QTabWidget()
        layout.addWidget(self._tabs)

        # === Console Tab ===
        self._console = QPlainTextEdit()
        self._console.setReadOnly(True)
        self._console.setMaximumBlockCount(10000)
        font = QFont("Consolas", 11)
        font.setStyleHint(QFont.Monospace)
        self._console.setFont(font)
        self._tabs.addTab(self._console, "Console Output")

        # === Results Tab ===
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)
        results_layout.setContentsMargins(4, 4, 4, 4)

        self._results_tree = QTreeWidget()
        self._results_tree.setHeaderLabels(["Key", "Value"])
        self._results_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._results_tree.header().setSectionResizeMode(1, QHeaderView.Stretch)
        self._results_tree.setAlternatingRowColors(True)
        results_layout.addWidget(self._results_tree)

        self._tabs.addTab(results_widget, "Structured Results")

        # === History Tab ===
        self._history = QTextEdit()
        self._history.setReadOnly(True)
        self._tabs.addTab(self._history, "History")

        # Bottom bar
        bottom = QHBoxLayout()
        self._status_label = QLabel("Ready")
        self._status_label.setObjectName("statusLabel")
        bottom.addWidget(self._status_label)

        bottom.addStretch()

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.clicked.connect(self.clear_console)
        bottom.addWidget(self._clear_btn)

        self._export_btn = QPushButton("Export")
        self._export_btn.clicked.connect(self._export_output)
        bottom.addWidget(self._export_btn)

        layout.addLayout(bottom)

        # Internal state
        self._current_result: Optional[ScanResult] = None
        self._history_results = []

    def clear_console(self):
        """Clear the console output."""
        self._console.clear()
        self._results_tree.clear()
        self._status_label.setText("Cleared")

    def append_line(self, line: str):
        """Append a line to the console output with color coding."""
        self._console.moveCursor(QTextCursor.End)

        # Colour-code output lines
        if line.startswith("[+]") or "[+]" in line:
            self._append_colored(line, "#00ff41")  # Green for findings
        elif line.startswith("[-]") or "[-]" in line:
            self._append_colored(line, "#808fa0")  # Grey for negatives
        elif line.startswith("[!]") or "[!]" in line:
            self._append_colored(line, "#ff6b6b")  # Red for warnings
        elif line.startswith("[*]") or "[*]" in line:
            self._append_colored(line, "#00d4ff")  # Cyan for info
        elif line.startswith("[ERROR]"):
            self._append_colored(line, "#ff4444")  # Bright red for errors
        elif line.startswith("=") or line.startswith("-"):
            self._append_colored(line, "#4a5568")  # Dim for separators
        else:
            self._console.appendPlainText(line)

        # Auto-scroll
        self._console.verticalScrollBar().setValue(
            self._console.verticalScrollBar().maximum()
        )

    def _append_colored(self, text: str, color: str):
        """Append colored text to console."""
        cursor = self._console.textCursor()
        cursor.movePosition(QTextCursor.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(text + "\n")
        # Reset color
        fmt.setForeground(QColor("#00ff41"))
        cursor.setCharFormat(fmt)

    def set_status(self, status: str):
        """Update the status label."""
        colors = {
            "running": "#ffaa00",
            "completed": "#00ff41",
            "failed": "#ff4444",
            "cancelled": "#ff6b6b",
            "idle": "#808fa0",
        }
        color = colors.get(status, "#e0e0e0")
        self._status_label.setText(status.upper())
        self._status_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def show_result(self, result: ScanResult):
        """Display structured result data in the results tree."""
        self._current_result = result
        self._results_tree.clear()

        # Metadata
        meta = QTreeWidgetItem(["Scan Metadata", ""])
        meta.setExpanded(True)
        QTreeWidgetItem(meta, ["Tool", result.tool_name])
        QTreeWidgetItem(meta, ["Status", result.status.value])
        if result.started_at:
            QTreeWidgetItem(meta, ["Started", result.started_at.strftime("%Y-%m-%d %H:%M:%S")])
        if result.duration_seconds is not None:
            QTreeWidgetItem(meta, ["Duration", f"{result.duration_seconds:.1f}s"])
        self._results_tree.addTopLevelItem(meta)

        # Parameters used
        if result.params_used:
            params_item = QTreeWidgetItem(["Parameters", ""])
            params_item.setExpanded(True)
            for k, v in result.params_used.items():
                QTreeWidgetItem(params_item, [k, str(v)])
            self._results_tree.addTopLevelItem(params_item)

        # Structured data
        if result.structured_data:
            self._add_dict_to_tree(result.structured_data, "Results")

        # Error
        if result.error_message:
            err = QTreeWidgetItem(["Error", ""])
            QTreeWidgetItem(err, ["Message", result.error_message])
            err.setForeground(0, QColor("#ff4444"))
            self._results_tree.addTopLevelItem(err)

        # Add to history
        self._add_to_history(result)

        # Switch to results tab
        self._tabs.setCurrentIndex(1)

    def _add_dict_to_tree(self, data: dict, parent_label: str):
        """Recursively add dict data to the tree widget."""
        parent = QTreeWidgetItem([parent_label, ""])
        parent.setExpanded(True)

        for key, value in data.items():
            if isinstance(value, dict):
                child = QTreeWidgetItem([str(key), ""])
                child.setExpanded(True)
                self._add_nested_dict(child, value)
                parent.addChild(child)
            elif isinstance(value, list):
                child = QTreeWidgetItem([str(key), f"({len(value)} items)"])
                child.setExpanded(len(value) <= 20)
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        sub = QTreeWidgetItem([f"[{i}]", ""])
                        self._add_nested_dict(sub, item)
                        child.addChild(sub)
                    else:
                        QTreeWidgetItem(child, [f"[{i}]", str(item)])
                parent.addChild(child)
            else:
                QTreeWidgetItem(parent, [str(key), str(value)])

        self._results_tree.addTopLevelItem(parent)

    def _add_nested_dict(self, parent: QTreeWidgetItem, data: dict):
        """Add nested dict entries to a tree item."""
        for k, v in data.items():
            if isinstance(v, dict):
                child = QTreeWidgetItem([str(k), ""])
                self._add_nested_dict(child, v)
                parent.addChild(child)
            elif isinstance(v, list):
                child = QTreeWidgetItem([str(k), f"({len(v)} items)"])
                for i, item in enumerate(v):
                    QTreeWidgetItem(child, [f"[{i}]", str(item)])
                parent.addChild(child)
            else:
                QTreeWidgetItem(parent, [str(k), str(v)])

    def _add_to_history(self, result: ScanResult):
        """Add a scan result to the history tab."""
        self._history_results.append(result)
        timestamp = result.started_at.strftime("%H:%M:%S") if result.started_at else "N/A"
        status_emoji = {
            ToolStatus.COMPLETED: "[OK]",
            ToolStatus.FAILED: "[FAIL]",
            ToolStatus.CANCELLED: "[CANCELLED]",
        }.get(result.status, "[?]")

        duration = f" ({result.duration_seconds:.1f}s)" if result.duration_seconds else ""
        entry = f"[{timestamp}] {status_emoji} {result.tool_name}{duration}"
        if result.params_used.get("target"):
            entry += f" -> {result.params_used['target']}"

        self._history.append(entry)

    def _export_output(self):
        """Export console output to a file."""
        text = self._console.toPlainText()
        if not text:
            return

        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Output", "",
            "Text Files (*.txt);;JSON Files (*.json);;All Files (*)"
        )
        if filepath:
            with open(filepath, "w") as f:
                if filepath.endswith(".json") and self._current_result:
                    import json
                    f.write(json.dumps(self._current_result.to_dict(), indent=2))
                else:
                    f.write(text)
