import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QColor
from gui import GUI

def dark_theme(app):
    app.setStyle("Fusion")
    palette = app.palette()

    palette.setColor(palette.Window, QColor(30, 30, 30))
    palette.setColor(palette.WindowText, QColor(255, 255, 255))
    palette.setColor(palette.Base, QColor(25, 25, 25))
    palette.setColor(palette.AlternateBase, QColor(35, 35, 35))
    palette.setColor(palette.Text, QColor(255, 255, 255))
    palette.setColor(palette.Button, QColor(40, 40, 40))
    palette.setColor(palette.ButtonText, QColor(255, 255, 255))

    app.setPalette(palette)

app = QApplication(sys.argv)
dark_theme(app)

window = GUI()
window.show()

sys.exit(app.exec_())