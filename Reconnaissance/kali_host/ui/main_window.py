"""
Main Window - the primary application window with tool sidebar, parameter form, and output panel.
"""
import os
import json
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTreeWidget, QTreeWidgetItem, QLabel, QPushButton, QProgressBar,
    QStatusBar, QMenuBar, QMenu, QAction, QMessageBox, QFileDialog,
    QScrollArea, QFrame, QApplication,
)
from PyQt5.QtCore import Qt, QSize, QTimer
from PyQt5.QtGui import QIcon, QFont

from ..core.models import (
    ToolDefinition, ToolCategory, ScanResult, ToolStatus, Project,
)
from ..core.registry import ToolRegistry
from ..core.runner import ToolRunner
from .param_form import ParamFormWidget
from .output_panel import OutputPanel
from .theme import DARK_STYLESHEET
from .settings_dialog import SettingsDialog


# Category icons (Unicode symbols as placeholders)
CATEGORY_ICONS = {
    ToolCategory.NETWORK_DISCOVERY: "\u26a1",   # Lightning
    ToolCategory.PORT_SCANNING: "\u2699",       # Gear
    ToolCategory.DNS_RECON: "\u2601",           # Cloud
    ToolCategory.WEB_RECON: "\u2602",           # Umbrella (web)
    ToolCategory.OSINT: "\u2709",               # Envelope
    ToolCategory.VULNERABILITY: "\u26a0",       # Warning
    ToolCategory.CUSTOM: "\u2726",              # Star
}


class MainWindow(QMainWindow):
    """Primary application window."""

    def __init__(self, registry: ToolRegistry):
        super().__init__()
        self._registry = registry
        self._runner = ToolRunner(registry)
        self._current_tool: ToolDefinition = None
        self._current_run_id: str = None
        self._project = Project(name="Default Project")

        self._setup_ui()
        self._setup_menu()
        self._populate_tool_tree()

    def _setup_ui(self):
        """Build the main UI layout."""
        self.setWindowTitle("Kali App Host")
        self.setMinimumSize(1200, 750)
        self.resize(1400, 850)
        self.setStyleSheet(DARK_STYLESHEET)

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Header bar
        header = self._create_header()
        main_layout.addWidget(header)

        # Main splitter: sidebar | params | output
        splitter = QSplitter(Qt.Horizontal)

        # === Left: Tool Sidebar ===
        sidebar_widget = QWidget()
        sidebar_layout = QVBoxLayout(sidebar_widget)
        sidebar_layout.setContentsMargins(8, 8, 4, 8)

        sidebar_title = QLabel("Tools")
        sidebar_title.setObjectName("headerLabel")
        sidebar_title.setStyleSheet("font-size: 16px; padding: 4px;")
        sidebar_layout.addWidget(sidebar_title)

        self._tool_tree = QTreeWidget()
        self._tool_tree.setHeaderHidden(True)
        self._tool_tree.setIndentation(20)
        self._tool_tree.setAnimated(True)
        self._tool_tree.itemClicked.connect(self._on_tool_selected)
        sidebar_layout.addWidget(self._tool_tree)

        sidebar_widget.setMinimumWidth(220)
        sidebar_widget.setMaximumWidth(320)
        splitter.addWidget(sidebar_widget)

        # === Middle: Parameter Form ===
        params_container = QWidget()
        params_layout = QVBoxLayout(params_container)
        params_layout.setContentsMargins(4, 8, 4, 8)

        # Scroll area for params
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        self._param_form = ParamFormWidget()
        scroll.setWidget(self._param_form)
        params_layout.addWidget(scroll)

        # Run / Cancel buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        self._run_btn = QPushButton("Run Tool")
        self._run_btn.setObjectName("runButton")
        self._run_btn.setEnabled(False)
        self._run_btn.clicked.connect(self._run_tool)
        btn_layout.addWidget(self._run_btn)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setObjectName("cancelButton")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._cancel_tool)
        btn_layout.addWidget(self._cancel_btn)

        btn_layout.addStretch()
        params_layout.addLayout(btn_layout)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setVisible(False)
        params_layout.addWidget(self._progress)

        params_container.setMinimumWidth(300)
        splitter.addWidget(params_container)

        # === Right: Output Panel ===
        self._output = OutputPanel()
        self._output.setMinimumWidth(450)
        splitter.addWidget(self._output)

        # Set splitter proportions
        splitter.setSizes([260, 340, 600])
        main_layout.addWidget(splitter)

        # Status bar
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)
        self._update_status_bar()

    def _create_header(self) -> QWidget:
        """Create the top header bar."""
        header = QWidget()
        header.setStyleSheet("""
            background-color: #0d1117;
            border-bottom: 2px solid #00d4ff;
        """)
        header.setFixedHeight(56)

        layout = QHBoxLayout(header)
        layout.setContentsMargins(16, 0, 16, 0)

        # App name
        title = QLabel("\u2620  Kali App Host")
        title.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: #00d4ff;
            font-family: "Consolas", monospace;
        """)
        layout.addWidget(title)

        layout.addStretch()

        # Project label
        self._project_label = QLabel(f"Project: {self._project.name}")
        self._project_label.setStyleSheet("color: #808fa0; font-size: 12px;")
        layout.addWidget(self._project_label)

        return header

    def _setup_menu(self):
        """Build the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        new_project = QAction("New Project", self)
        new_project.setShortcut("Ctrl+N")
        new_project.triggered.connect(self._new_project)
        file_menu.addAction(new_project)

        open_project = QAction("Open Project", self)
        open_project.setShortcut("Ctrl+O")
        open_project.triggered.connect(self._open_project)
        file_menu.addAction(open_project)

        save_project = QAction("Save Project", self)
        save_project.setShortcut("Ctrl+S")
        save_project.triggered.connect(self._save_project)
        file_menu.addAction(save_project)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Settings menu
        settings_menu = menubar.addMenu("Settings")

        api_keys_action = QAction("API Keys...", self)
        api_keys_action.setShortcut("Ctrl+,")
        api_keys_action.setToolTip("Configure API keys for OSINT services")
        api_keys_action.triggered.connect(self._open_settings)
        settings_menu.addAction(api_keys_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        reload_plugins = QAction("Reload Plugins", self)
        reload_plugins.setShortcut("F5")
        reload_plugins.triggered.connect(self._reload_plugins)
        tools_menu.addAction(reload_plugins)

        # Help menu
        help_menu = menubar.addMenu("Help")
        about = QAction("About", self)
        about.triggered.connect(self._show_about)
        help_menu.addAction(about)

    def _populate_tool_tree(self):
        """Fill the sidebar tree with discovered tools grouped by category."""
        self._tool_tree.clear()

        for category in self._registry.get_all_categories():
            icon = CATEGORY_ICONS.get(category, "\u2726")
            cat_item = QTreeWidgetItem([f"{icon}  {category.value}"])
            cat_item.setExpanded(True)
            cat_item.setData(0, Qt.UserRole, None)  # Not a tool

            font = cat_item.font(0)
            font.setBold(True)
            cat_item.setFont(0, font)

            tools = self._registry.get_tools_by_category(category)
            for tool in sorted(tools, key=lambda t: t.name):
                tool_item = QTreeWidgetItem([f"  {tool.name}"])
                tool_item.setData(0, Qt.UserRole, tool.tool_id)
                tool_item.setToolTip(0, tool.description)
                cat_item.addChild(tool_item)

            self._tool_tree.addTopLevelItem(cat_item)

    def _on_tool_selected(self, item: QTreeWidgetItem, column: int):
        """Handle tool selection from sidebar."""
        tool_id = item.data(0, Qt.UserRole)
        if not tool_id:
            return  # Category header clicked

        tool_def = self._registry.get_tool(tool_id)
        if tool_def:
            self._current_tool = tool_def
            self._param_form.load_tool(tool_def)
            self._run_btn.setEnabled(True)
            self._statusbar.showMessage(f"Selected: {tool_def.name}")

    def _run_tool(self):
        """Execute the selected tool."""
        if not self._current_tool:
            return

        # Validate params
        valid, error = self._param_form.validate()
        if not valid:
            QMessageBox.warning(self, "Validation Error", error)
            return

        params = self._param_form.get_params()

        # Update UI state
        self._run_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._progress.setVisible(True)
        self._progress.setValue(0)
        self._output.clear_console()
        self._output.set_status("running")

        # Banner
        self._output.append_line(f"[*] Starting {self._current_tool.name}...")
        self._output.append_line(f"[*] Target: {params.get('target', 'N/A')}")
        self._output.append_line("")

        # Run tool
        try:
            self._current_run_id = self._runner.run_tool(
                tool_id=self._current_tool.tool_id,
                params=params,
                on_output=self._on_tool_output,
                on_status=self._on_tool_status,
                on_progress=self._on_tool_progress,
                on_finished=self._on_tool_finished,
                on_error=self._on_tool_error,
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start tool: {e}")
            self._reset_run_state()

    def _cancel_tool(self):
        """Cancel the running tool."""
        if self._current_run_id:
            self._runner.cancel(self._current_run_id)
            self._output.append_line("\n[!] Cancelling...")

    def _on_tool_output(self, line: str):
        """Handle real-time output from tool."""
        self._output.append_line(line)

    def _on_tool_status(self, status: str):
        """Handle status change from tool."""
        self._output.set_status(status)
        self._statusbar.showMessage(f"Status: {status}")

    def _on_tool_progress(self, current: int, total: int):
        """Handle progress update from tool."""
        if total > 0:
            self._progress.setMaximum(total)
            self._progress.setValue(current)

    def _on_tool_finished(self, result: ScanResult):
        """Handle tool completion."""
        self._output.show_result(result)
        self._project.results.append(result)
        self._reset_run_state()

        duration = f" in {result.duration_seconds:.1f}s" if result.duration_seconds else ""
        self._statusbar.showMessage(
            f"{result.tool_name}: {result.status.value}{duration}"
        )

    def _on_tool_error(self, error: str):
        """Handle tool error."""
        self._output.append_line(f"\n[ERROR] {error}")

    def _reset_run_state(self):
        """Reset UI after a tool run completes."""
        self._run_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._progress.setVisible(False)
        self._current_run_id = None

    def _new_project(self):
        """Create a new project."""
        self._project = Project(name="New Project")
        self._project_label.setText(f"Project: {self._project.name}")
        self._output.clear_console()
        self._statusbar.showMessage("New project created")

    def _open_project(self):
        """Open a saved project file."""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Open Project", "", "JSON Files (*.json)"
        )
        if filepath:
            try:
                with open(filepath, "r") as f:
                    self._project = Project.from_json(f.read())
                self._project_label.setText(f"Project: {self._project.name}")
                self._statusbar.showMessage(f"Opened: {self._project.name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open project: {e}")

    def _save_project(self):
        """Save the current project."""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save Project", f"{self._project.name}.json", "JSON Files (*.json)"
        )
        if filepath:
            try:
                with open(filepath, "w") as f:
                    f.write(self._project.to_json())
                self._statusbar.showMessage(f"Saved: {filepath}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save: {e}")

    def _open_settings(self):
        """Open the API Keys settings dialog."""
        dlg = SettingsDialog(parent=self)
        dlg.exec_()

    def _reload_plugins(self):
        """Reload tool plugins from disk."""
        count = self._registry.discover_tools()
        self._populate_tool_tree()
        self._statusbar.showMessage(f"Reloaded: {count} tool(s) found")

    def _show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About Kali App Host",
            "<h2>Kali App Host</h2>"
            "<p>Version 0.1.0</p>"
            "<p>A Windows desktop application for hosting and running "
            "Kali Python reconnaissance tools.</p>"
            "<p>Tools are loaded as plugins via YAML definitions.</p>"
        )

    def _update_status_bar(self):
        """Update status bar with tool count."""
        count = len(self._registry.tools)
        self._statusbar.showMessage(f"Ready | {count} tool(s) loaded")

    def closeEvent(self, event):
        """Handle window close - cancel any running tools."""
        self._runner.cancel_all()
        event.accept()
