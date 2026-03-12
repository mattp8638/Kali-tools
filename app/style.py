"""
Unified stylesheet for the top-level application shell.
Phase accent colours are applied dynamically per phase.
"""

APP_STYLE = """
/* === Global === */
QMainWindow, QWidget {
    background-color: #0d0d0d;
    color: #d8d8d8;
    font-family: 'Segoe UI', 'Consolas', monospace;
    font-size: 13px;
}

/* === Left sidebar === */
#sidebar {
    background-color: #0a0a0a;
    border-right: 1px solid #222;
    min-width: 210px;
    max-width: 210px;
}
#sidebarTitle {
    font-size: 11px;
    font-weight: bold;
    color: #444;
    letter-spacing: 2px;
    text-transform: uppercase;
    padding: 8px 16px 4px 16px;
}

/* === Nav buttons === */
QPushButton#navBtn {
    background: transparent;
    color: #888;
    border: none;
    border-left: 3px solid transparent;
    border-radius: 0;
    text-align: left;
    padding: 10px 16px;
    font-size: 13px;
    font-weight: normal;
    min-width: 0;
}
QPushButton#navBtn:hover {
    background-color: #151515;
    color: #ccc;
}
QPushButton#navBtn[active="true"] {
    color: #ffffff;
    font-weight: bold;
    background-color: #151515;
}

/* Full pentest button — always visible gold accent */
QPushButton#fullPentestBtn {
    background: #1a1500;
    color: #ffcc00;
    border: none;
    border-left: 3px solid #ffcc00;
    border-radius: 0;
    text-align: left;
    padding: 12px 16px;
    font-size: 13px;
    font-weight: bold;
    min-width: 0;
}
QPushButton#fullPentestBtn:hover {
    background: #222000;
}

/* === Content area === */
#contentStack {
    background-color: #111;
}

/* === Phase header banner === */
#phaseHeader {
    min-height: 52px;
    max-height: 52px;
    border-bottom: 1px solid #222;
}
#phaseTitle {
    font-size: 19px;
    font-weight: bold;
    font-family: 'Consolas', monospace;
    padding-left: 4px;
}
#phaseSubtitle {
    font-size: 11px;
    color: #666;
    padding-left: 6px;
}

/* === Tool tree (left sub-panel inside phase) === */
QTreeWidget {
    background-color: #0d0d0d;
    border: none;
    border-right: 1px solid #1e1e1e;
    outline: none;
}
QTreeWidget::item {
    padding: 7px 10px;
    border-radius: 3px;
    color: #aaa;
}
QTreeWidget::item:hover  { background: #161616; color: #ddd; }
QTreeWidget::item:selected { background: #1e1e1e; color: #fff; }
QHeaderView::section {
    background: #0a0a0a; color: #555;
    border: none; border-bottom: 1px solid #1e1e1e;
    padding: 5px; font-weight: bold; font-size: 11px;
}

/* === Params / forms === */
QLineEdit, QComboBox, QSpinBox {
    background: #111; color: #ddd;
    border: 1px solid #2a2a2a; border-radius: 4px;
    padding: 7px 10px;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #555; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView {
    background: #111; color: #ddd;
    border: 1px solid #333;
    selection-background-color: #2a2a2a;
}
QCheckBox { color: #aaa; spacing: 8px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #333; border-radius: 3px;
    background: #111;
}
QCheckBox::indicator:checked { background: #555; border-color: #888; }

/* === Buttons === */
QPushButton {
    background: #1e1e1e; color: #ccc;
    border: 1px solid #333; border-radius: 4px;
    padding: 8px 18px; font-weight: bold;
}
QPushButton:hover  { background: #252525; border-color: #555; }
QPushButton:pressed{ background: #111; }
QPushButton:disabled{ color: #444; border-color: #1e1e1e; }
QPushButton#runBtn {
    background: #063; color: #fff;
    border-color: #0a5; font-size: 13px;
}
QPushButton#runBtn:hover { background: #074; }
QPushButton#cancelBtn {
    background: #500; color: #fff;
    border-color: #800;
}
QPushButton#cancelBtn:hover { background: #700; }

/* === Output / log === */
QPlainTextEdit, QTextEdit {
    background: #080808; color: #b0b0b0;
    border: 1px solid #1a1a1a; border-radius: 4px;
    font-family: 'Consolas', monospace; font-size: 12px;
    padding: 6px;
    selection-background-color: #2a2a2a;
}

/* === Progress bar === */
QProgressBar {
    background: #111; border: 1px solid #222;
    border-radius: 4px; height: 8px; text-align: center;
}
QProgressBar::chunk { border-radius: 3px; }

/* === Tabs === */
QTabWidget::pane { border: 1px solid #222; background: #111; }
QTabBar::tab {
    background: #0d0d0d; color: #666;
    border: 1px solid #222; border-bottom: none;
    padding: 7px 16px; margin-right: 2px;
    border-top-left-radius: 4px; border-top-right-radius: 4px;
}
QTabBar::tab:selected { background: #111; color: #ddd; border-bottom: 2px solid #555; }
QTabBar::tab:hover { color: #aaa; }

/* === Group boxes === */
QGroupBox {
    border: 1px solid #222; border-radius: 5px;
    margin-top: 12px; padding-top: 16px;
    color: #666; font-weight: bold;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }

/* === Scroll bars === */
QScrollBar:vertical { background: #0d0d0d; width: 8px; border: none; }
QScrollBar::handle:vertical { background: #2a2a2a; border-radius: 4px; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: #3a3a3a; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #0d0d0d; height: 8px; border: none; }
QScrollBar::handle:horizontal { background: #2a2a2a; border-radius: 4px; min-width: 24px; }

/* === Status bar === */
QStatusBar { background: #0a0a0a; color: #555; border-top: 1px solid #1a1a1a; font-size: 11px; }

/* === Labels === */
QLabel { color: #aaa; }
QLabel#sectionLabel { font-size: 11px; color: #555; font-weight: bold; letter-spacing: 1px; }
QLabel#fieldLabel    { color: #777; font-size: 12px; }
QLabel#badgeCritical { color: #ff3030; font-weight: bold; }
QLabel#badgeHigh     { color: #ff6b35; font-weight: bold; }
QLabel#badgeMedium   { color: #ffaa00; font-weight: bold; }
QLabel#badgeLow      { color: #ffd966; }
QLabel#badgeInfo     { color: #666; }

/* === Splitter === */
QSplitter::handle { background: #1a1a1a; }
QSplitter::handle:horizontal { width: 1px; }
QSplitter::handle:vertical   { height: 1px; }

/* === Tooltip === */
QToolTip { background: #111; color: #ccc; border: 1px solid #333; padding: 4px 8px; }
"""

PHASE_ACCENTS = {
    "recon":       "#00aaff",
    "scanning":    "#00cc66",
    "va":          "#ffaa00",
    "exploitation":"#ff3300",
    "reporting":   "#cc88ff",
    "fullpentest": "#ffcc00",
}
