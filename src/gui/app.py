import sys

from PySide6.QtWidgets import QApplication

from main_window import MainWindow


app = QApplication(sys.argv)

window = MainWindow()
window.showMaximized()

sys.exit(app.exec())