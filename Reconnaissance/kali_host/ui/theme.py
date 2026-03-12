"""
Dark theme stylesheet - Kali-inspired dark theme for the app.
"""

DARK_STYLESHEET = """
/* ===== Global ===== */
QMainWindow, QWidget {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: "Segoe UI", "Consolas", monospace;
    font-size: 13px;
}

/* ===== Menu Bar ===== */
QMenuBar {
    background-color: #16213e;
    color: #e0e0e0;
    border-bottom: 1px solid #0f3460;
    padding: 2px;
}
QMenuBar::item:selected {
    background-color: #0f3460;
}
QMenu {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
}
QMenu::item:selected {
    background-color: #0f3460;
}

/* ===== Tool Bar ===== */
QToolBar {
    background-color: #16213e;
    border-bottom: 1px solid #0f3460;
    spacing: 4px;
    padding: 4px;
}

/* ===== Splitter ===== */
QSplitter::handle {
    background-color: #0f3460;
    width: 2px;
}

/* ===== Tree / List Views ===== */
QTreeWidget, QListWidget {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 4px;
    outline: none;
    padding: 4px;
}
QTreeWidget::item, QListWidget::item {
    padding: 6px 8px;
    border-radius: 3px;
}
QTreeWidget::item:selected, QListWidget::item:selected {
    background-color: #0f3460;
    color: #00d4ff;
}
QTreeWidget::item:hover, QListWidget::item:hover {
    background-color: #1a2745;
}
QHeaderView::section {
    background-color: #16213e;
    color: #808fa0;
    border: none;
    border-bottom: 1px solid #0f3460;
    padding: 6px;
    font-weight: bold;
}

/* ===== Text Edit / Output ===== */
QTextEdit, QPlainTextEdit {
    background-color: #0d1117;
    color: #00ff41;
    border: 1px solid #0f3460;
    border-radius: 4px;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
    padding: 8px;
    selection-background-color: #0f3460;
}

/* ===== Line Edit ===== */
QLineEdit {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 13px;
}
QLineEdit:focus {
    border-color: #00d4ff;
}
QLineEdit::placeholder {
    color: #4a5568;
}

/* ===== Combo Box ===== */
QComboBox {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 6px 12px;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox QAbstractItemView {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    selection-background-color: #0f3460;
}

/* ===== Check Box ===== */
QCheckBox {
    color: #e0e0e0;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 1px solid #0f3460;
    border-radius: 3px;
    background-color: #16213e;
}
QCheckBox::indicator:checked {
    background-color: #00d4ff;
    border-color: #00d4ff;
}

/* ===== Buttons ===== */
QPushButton {
    background-color: #0f3460;
    color: #e0e0e0;
    border: 1px solid #1a4a7a;
    border-radius: 4px;
    padding: 8px 20px;
    font-weight: bold;
    min-width: 80px;
}
QPushButton:hover {
    background-color: #1a4a7a;
    border-color: #00d4ff;
}
QPushButton:pressed {
    background-color: #0a2340;
}
QPushButton:disabled {
    background-color: #1a1a2e;
    color: #4a5568;
    border-color: #2a2a3e;
}
QPushButton#runButton {
    background-color: #006644;
    border-color: #00aa66;
    color: #ffffff;
}
QPushButton#runButton:hover {
    background-color: #008855;
}
QPushButton#cancelButton {
    background-color: #8b0000;
    border-color: #cc0000;
    color: #ffffff;
}
QPushButton#cancelButton:hover {
    background-color: #aa0000;
}

/* ===== Tab Widget ===== */
QTabWidget::pane {
    border: 1px solid #0f3460;
    background-color: #1a1a2e;
    border-radius: 4px;
}
QTabBar::tab {
    background-color: #16213e;
    color: #808fa0;
    border: 1px solid #0f3460;
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}
QTabBar::tab:selected {
    background-color: #1a1a2e;
    color: #00d4ff;
    border-bottom: 2px solid #00d4ff;
}
QTabBar::tab:hover {
    color: #e0e0e0;
}

/* ===== Progress Bar ===== */
QProgressBar {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    text-align: center;
    color: #e0e0e0;
    height: 20px;
}
QProgressBar::chunk {
    background-color: #00d4ff;
    border-radius: 3px;
}

/* ===== Status Bar ===== */
QStatusBar {
    background-color: #16213e;
    color: #808fa0;
    border-top: 1px solid #0f3460;
}

/* ===== Group Box ===== */
QGroupBox {
    border: 1px solid #0f3460;
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 16px;
    font-weight: bold;
    color: #00d4ff;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}

/* ===== Scroll Bar ===== */
QScrollBar:vertical {
    background-color: #1a1a2e;
    width: 10px;
    border: none;
}
QScrollBar::handle:vertical {
    background-color: #0f3460;
    border-radius: 5px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background-color: #1a4a7a;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QScrollBar:horizontal {
    background-color: #1a1a2e;
    height: 10px;
    border: none;
}
QScrollBar::handle:horizontal {
    background-color: #0f3460;
    border-radius: 5px;
    min-width: 30px;
}

/* ===== Labels ===== */
QLabel {
    color: #e0e0e0;
}
QLabel#headerLabel {
    font-size: 18px;
    font-weight: bold;
    color: #00d4ff;
}
QLabel#categoryLabel {
    font-size: 11px;
    color: #808fa0;
    text-transform: uppercase;
    font-weight: bold;
    letter-spacing: 1px;
}
QLabel#statusLabel {
    color: #00ff41;
    font-weight: bold;
}

/* ===== Dock Widget ===== */
QDockWidget {
    color: #e0e0e0;
    titlebar-close-icon: none;
}
QDockWidget::title {
    background-color: #16213e;
    padding: 8px;
    border-bottom: 1px solid #0f3460;
}

/* ===== Tooltip ===== */
QToolTip {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    padding: 4px 8px;
}

/* ===== Spin Box ===== */
QSpinBox {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 6px;
}
QSpinBox:focus {
    border-color: #00d4ff;
}
"""
