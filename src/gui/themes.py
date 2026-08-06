# src/gui/themes.py

LIGHT_THEME = """
QMainWindow {
    background-color: #EEF2F7;
}

QWidget {
    background-color: #EEF2F7;
    color: #202124;
    font-family: "Segoe UI Variable", "Segoe UI";
    font-size: 10pt;
}

QFrame#ContentFrame {
    background: #FFFFFF;
    border: 1px solid #E5E7EB;
    border-radius: 20px;
}

QLabel#Title {
    font-size: 30px;
    font-weight: 700;
    color: #202124;
}

QLabel#Subtitle {
    font-size: 14px;
    color: #5F6368;
}

QPushButton {
    background: #2563EB;
    color: white;
    border: none;
    border-radius: 12px;
    padding: 12px 24px;
    min-height: 42px;
    font-size: 11pt;
    font-weight: 600;
}

QPushButton:hover {
    background: #3B82F6;
}

QPushButton:pressed {
    background: #1D4ED8;
}

QPushButton:disabled {
    background: #9CA3AF;
    color: #E5E7EB;
}

QPushButton#IconButton {
    background: transparent;
    border: none;
    border-radius: 18px;
    padding: 8px;
    font-size: 16px;
}

QPushButton#IconButton:hover {
    background: #E9EEF8;
}

QPushButton#IconButton:pressed {
    background: #D8E4F5;
}

QFrame#DropArea {
    background: white;
    border: 2px dashed #B8C1CC;
    border-radius:20px;
    min-height:240px;
}

QFrame#DropArea[dragging="true"] {
    border: 2px solid #2563EB;
    background: #EEF5FF;
}

QFrame#DropArea QLabel {
    background: transparent;
}
QFrame#DropArea:hover {
    border: 2px solid #60A5FA;
}

QFrame#Card{
    background:white;
    border-radius:18px;
    border:1px solid #E5E7EB;
}

QScrollBar:vertical{
    background:transparent;
    width:8px;
}

QScrollBar::handle:vertical{
    background:#A0AEC0;
    border-radius:4px;
}

QScrollBar::handle:vertical:hover{
    background:#718096;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical{
    height:0;
}

QLabel{
    background: transparent;
    selection-background-color:#2563EB;
}
"""


DARK_THEME = """
QMainWindow {
    background-color: #111315;
}


QWidget {
    background-color: #111315;
    color: white;
    font-family: "Segoe UI Variable", "Segoe UI";
    font-size: 10pt;
}

QFrame#ContentFrame {
    background: #1E1E1E;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
}

QLabel#Title {
    font-size: 34px;
    font-weight: 700;
    letter-spacing:0.5px;
    color: white;
}

QLabel#Subtitle {
    font-size: 15px;
    color: #B0B0B0;
}

QPushButton {
    background: #3B82F6;
    color: white;
    border: none;
    border-radius: 12px;
    padding: 12px 24px;
    min-height: 42px;
    font-size: 11pt;
    font-weight: 600;
}

QPushButton:hover {
    background: #60A5FA;
}

QPushButton:pressed {
    background: #2563EB;
}

QPushButton:disabled {
    background: #404040;
    color: #909090;
}

QPushButton#IconButton {
    background: transparent;
    border: none;
    border-radius: 18px;
    padding: 8px;
    font-size: 16px;
}

QPushButton#IconButton:hover {
    background: #2B2B2B;
}

QPushButton#IconButton:pressed {
    background: #383838;
}

QFrame#DropArea {
    background: #1E1E1E;
    border: 2px dashed #505050;
    border-radius: 18px;
}

QFrame#DropArea[dragging="true"] {
    border: 2px solid #4F8EF7;
    background: #232E44;
}

QFrame#DropArea QLabel {
    background: transparent;
}
QFrame#DropArea:hover {
    border: 2px solid #60A5FA;
}

QFrame#Card{
    background:#1F1F1F;
    border-radius:18px;
    border:1px solid #343434;
}

QScrollBar:vertical{
    background:transparent;
    width:8px;
}

QScrollBar::handle:vertical{
    background:#A0AEC0;
    border-radius:4px;
}

QScrollBar::handle:vertical:hover{
    background:#718096;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical{
    height:0;
}

QLabel{
    background: transparent;
    selection-background-color:#3B82F6;
}
"""