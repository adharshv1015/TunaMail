from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QVBoxLayout,
    QFileDialog
)


class DropArea(QFrame):
    fileSelected = Signal(str)

    def __init__(self):
        super().__init__()

        self.selected_file = None

        self.setAcceptDrops(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setObjectName("DropArea")

        self.setMinimumHeight(220)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(10)

        self.title = QLabel("📄 Drag & Drop an .eml file")
        self.title.setAlignment(Qt.AlignCenter)

        self.subtitle = QLabel("or click here to browse")
        self.subtitle.setAlignment(Qt.AlignCenter)

        self.filename = QLabel("No file selected")
        self.filename.setAlignment(Qt.AlignCenter)

        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)
        layout.addWidget(self.filename)

    # -------------------------
    # Mouse Click
    # -------------------------

    def mousePressEvent(self, event):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Email",
            "",
            "Email Files (*.eml)"
        )

        if file_path:
            self.set_file(file_path)

    # -------------------------
    # Drag Events
    # -------------------------

    def dragEnterEvent(self, event):

        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setProperty("dragging", True)
            self.style().polish(self)
        else:
            event.ignore()

    def dragLeaveEvent(self, event):

        self.setProperty("dragging", False)
        self.style().polish(self)

    def dropEvent(self, event):

        self.setProperty("dragging", False)
        self.style().polish(self)

        urls = event.mimeData().urls()

        if urls:

            path = urls[0].toLocalFile()

            if path.lower().endswith(".eml"):
                self.set_file(path)

    def set_file(self, path):

        self.selected_file = path

        filename = path.split("/")[-1].split("\\")[-1]

        self.filename.setText(filename)

        self.fileSelected.emit(path)