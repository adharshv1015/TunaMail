from pathlib import Path
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QLabel,
    QPushButton,
    QMessageBox,
    QFileDialog,
)
from PySide6.QtCore import Qt

from report_window import ReportWindow
import themes


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.is_dark_mode = False
        self.selected_file = None

        # Setup core central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(25, 20, 25, 20)
        self.main_layout.setSpacing(0)

        # Build UI in order
        self.build_window()
        self.build_top_bar()
        self.main_layout.addStretch()
        self.build_center_content()
        self.main_layout.addStretch()
        self.apply_theme()

    def build_window(self):
        self.setWindowTitle("TunaMail")
        self.setMinimumSize(1200, 800)
        self.showMaximized()

    def build_top_bar(self):
        top_bar = QHBoxLayout()
        top_bar.addStretch()

        self.theme_button = QPushButton("🌙")
        self.theme_button.setObjectName("IconButton")
        self.theme_button.setFixedSize(42, 42)
        self.theme_button.clicked.connect(self.toggle_theme)
        
        top_bar.addWidget(self.theme_button)
        self.main_layout.addLayout(top_bar)

    def build_center_content(self):
        self.content_frame = QFrame()
        self.content_frame.setObjectName("ContentFrame")
        self.content_frame.setFixedWidth(720)
        self.content_frame.setFixedHeight(760)

        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(self.content_frame)
        row.addStretch()
        self.main_layout.addLayout(row)

        self.content_layout = QVBoxLayout(self.content_frame)
        self.content_layout.setContentsMargins(50, 50, 50, 50)
        self.content_layout.setSpacing(25)
        self.content_layout.setAlignment(Qt.AlignCenter)

        # Title
        self.title = QLabel("TunaMail")
        self.title.setObjectName("Title")
        self.title.setAlignment(Qt.AlignCenter)
        
        title_font = self.title.font()
        title_font.setPointSize(34)
        title_font.setBold(True)
        self.title.setFont(title_font)
        
        self.content_layout.addWidget(self.title)

        # Subtitle
        self.subtitle = QLabel(
            "Upload a .eml file to analyze email authenticity\nand phishing indicators."
        )
        self.subtitle.setObjectName("Subtitle")
        self.subtitle.setWordWrap(True)
        self.subtitle.setAlignment(Qt.AlignCenter)
        self.content_layout.addWidget(self.subtitle)

        self.content_layout.addStretch(1)
        self.build_drop_area()
        
        # Filename Label (Under Drop Area)
        self.filename_label = QLabel("No file selected")
        self.filename_label.setObjectName("FilenameLabel")
        self.filename_label.setAlignment(Qt.AlignCenter)
        self.content_layout.addWidget(self.filename_label)
        
        self.content_layout.addStretch(1)
        self.build_buttons()

    def build_drop_area(self):
        self.drop_area = QFrame()
        self.drop_area.setObjectName("DropArea")
        self.drop_area.setFixedSize(520, 250)

        layout = QVBoxLayout(self.drop_area)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(15)

        # 1. Upload Icon
        self.drop_icon = QLabel("📄")
        self.drop_icon.setAlignment(Qt.AlignCenter)
        font = self.drop_icon.font()
        font.setPointSize(42)
        self.drop_icon.setFont(font)

        # 2. Drag & Drop Text
        self.drop_label = QLabel("Drag & Drop your .eml file")
        self.drop_label.setAlignment(Qt.AlignCenter)
        font2 = self.drop_label.font()
        font2.setPointSize(13)
        font2.setBold(True)
        self.drop_label.setFont(font2)

        # 3. Browse Files Text
        self.drop_browse_label = QLabel("Browse Files")
        self.drop_browse_label.setAlignment(Qt.AlignCenter)
        self.drop_browse_label.setObjectName("DropBrowseLabel")

        layout.addWidget(self.drop_icon)
        layout.addWidget(self.drop_label)
        layout.addWidget(self.drop_browse_label)

        self.content_layout.addWidget(self.drop_area)

    def build_buttons(self):
        button_row = QHBoxLayout()
        button_row.setSpacing(15)
        button_row.setAlignment(Qt.AlignCenter)

        self.browse_button = QPushButton("Browse File")
        self.browse_button.setFixedSize(200, 48)
        self.browse_button.clicked.connect(self.browse_file)

        self.analyze_button = QPushButton("▶ Start Check")
        self.analyze_button.setFixedSize(200, 48)
        self.analyze_button.clicked.connect(self.show_report_window)
        self.analyze_button.setEnabled(False)

        button_row.addWidget(self.browse_button)
        button_row.addWidget(self.analyze_button)

        self.content_layout.addLayout(button_row)

    def browse_file(self):
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select EML File",
            "",
            "Email Files (*.eml)"
        )

        if not filename:
            return

        self.selected_file = filename

        # Update UI: Filename label directly below drop area
        self.filename_label.setText(f"✔ {Path(filename).name}")

        # Enable Start Check
        self.analyze_button.setEnabled(True)

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        
        # Swap the icon depending on mode
        if self.is_dark_mode:
            self.theme_button.setText("🌞")
        else:
            self.theme_button.setText("🌙")
            
        self.apply_theme()

    def apply_theme(self):
        if self.is_dark_mode:
            self.setStyleSheet(themes.DARK_THEME)
        else:
            self.setStyleSheet(themes.LIGHT_THEME)

    def show_report_window(self):
        if not self.selected_file:
            QMessageBox.warning(self, "No File Selected", "Please select an .eml file to analyze first.")
            return

        # We store the reference so the window isn't garbage collected
        self.report_window = ReportWindow()
        self.report_window.showMaximized()