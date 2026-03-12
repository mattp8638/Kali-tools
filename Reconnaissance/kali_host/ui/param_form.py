"""
Dynamic parameter form - generates input widgets from tool definitions.
"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QSpinBox, QCheckBox, QComboBox, QFormLayout, QGroupBox,
)
from PyQt5.QtCore import Qt
from typing import Dict, Any

from ..core.models import ToolDefinition, ToolParam, ParamType


class ParamFormWidget(QWidget):
    """Dynamically generates a form based on tool parameters."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._widgets: Dict[str, QWidget] = {}
        self._param_defs: Dict[str, ToolParam] = {}
        self._current_tool: ToolDefinition = None

        # Placeholder
        self._placeholder = QLabel("Select a tool from the sidebar")
        self._placeholder.setAlignment(Qt.AlignCenter)
        self._placeholder.setStyleSheet("color: #4a5568; font-size: 14px;")
        self._layout.addWidget(self._placeholder)

    def load_tool(self, tool_def: ToolDefinition):
        """Build form for a tool's parameters."""
        self._current_tool = tool_def
        self._clear_form()

        # Tool header
        header = QLabel(tool_def.name)
        header.setObjectName("headerLabel")
        self._layout.addWidget(header)

        desc = QLabel(tool_def.description)
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #808fa0; margin-bottom: 12px;")
        self._layout.addWidget(desc)

        # Parameters group
        if tool_def.params:
            group = QGroupBox("Parameters")
            form = QFormLayout()
            form.setSpacing(12)
            form.setContentsMargins(12, 20, 12, 12)

            for param in tool_def.params:
                widget = self._create_widget(param)
                label_text = param.label
                if param.required:
                    label_text += " *"
                label = QLabel(label_text)
                label.setToolTip(param.help_text)

                form.addRow(label, widget)
                self._widgets[param.name] = widget
                self._param_defs[param.name] = param

                # Help text below the field
                if param.help_text:
                    help_label = QLabel(param.help_text)
                    help_label.setStyleSheet("color: #4a5568; font-size: 11px; margin-top: -4px;")
                    help_label.setWordWrap(True)
                    form.addRow("", help_label)

            group.setLayout(form)
            self._layout.addWidget(group)

        self._layout.addStretch()

    def get_params(self) -> Dict[str, Any]:
        """Collect current parameter values from the form."""
        params = {}
        for name, widget in self._widgets.items():
            param_def = self._param_defs[name]

            if isinstance(widget, QLineEdit):
                value = widget.text().strip()
                if not value and param_def.default is not None:
                    value = str(param_def.default)
                params[name] = value

            elif isinstance(widget, QSpinBox):
                params[name] = widget.value()

            elif isinstance(widget, QCheckBox):
                params[name] = widget.isChecked()

            elif isinstance(widget, QComboBox):
                params[name] = widget.currentText()

        return params

    def validate(self) -> tuple:
        """Validate required fields. Returns (is_valid, error_message)."""
        for name, param_def in self._param_defs.items():
            if param_def.required:
                widget = self._widgets[name]
                if isinstance(widget, QLineEdit):
                    if not widget.text().strip():
                        return False, f"{param_def.label} is required"
        return True, ""

    def _create_widget(self, param: ToolParam) -> QWidget:
        """Create appropriate widget for a parameter type."""
        if param.param_type == ParamType.BOOLEAN:
            widget = QCheckBox()
            if param.default is not None:
                widget.setChecked(bool(param.default))
            return widget

        if param.param_type == ParamType.INTEGER:
            widget = QSpinBox()
            widget.setRange(0, 99999)
            if param.default is not None:
                widget.setValue(int(param.default))
            return widget

        if param.param_type == ParamType.CHOICE:
            widget = QComboBox()
            widget.addItems(param.choices)
            if param.default and param.default in param.choices:
                widget.setCurrentText(param.default)
            return widget

        # Default: text input for string, ip_address, domain, port_range, etc.
        widget = QLineEdit()
        if param.placeholder:
            widget.setPlaceholderText(param.placeholder)
        if param.default is not None:
            widget.setText(str(param.default))
        return widget

    def _clear_form(self):
        """Remove all widgets from the form."""
        self._widgets.clear()
        self._param_defs.clear()
        while self._layout.count():
            item = self._layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
