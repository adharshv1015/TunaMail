import sys

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
)
from PySide6.QtWidgets import QApplication

# pyrefly: ignore [missing-import]
from main_window import MainWindow


app = QApplication(sys.argv)

window = MainWindow()
window.show()

sys.exit(app.exec())