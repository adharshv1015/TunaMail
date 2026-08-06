import os
from PySide6.QtWidgets import QMainWindow
from PySide6.QtCore import QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView

class ReportWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Analysis Report")
        
        # Create web viewer
        self.browser = QWebEngineView()
        self.setCentralWidget(self.browser)
        
        # Load report.html from the same directory
        local_dir = os.path.dirname(os.path.abspath(__file__))
        report_path = os.path.join(local_dir, "report.html")
        
        # Set url using QUrl.fromLocalFile for safe local path resolving
        url = QUrl.fromLocalFile(report_path)
        self.browser.setUrl(url)
