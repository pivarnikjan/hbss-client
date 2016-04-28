import os, sys
from PyQt4 import QtGui, QtCore


class MainWindow(QtGui.QWidget):
    def __init__(self):
        QtGui.QWidget.__init__(self)

        self.setGeometry(0, 0, 500, 650)
        self.setWindowTitle("Quantum Subscriber")
        self.setWindowIcon(QtGui.QIcon("icon.png"))
        self.resize(500, 650)
        self.setMinimumSize(500, 650)
        self.center()
        self.set_layout()

    def set_layout(self):
        # --- Menu --- #
        open = QtGui.QAction("Exit", self)
        save = QtGui.QAction("Save", self)
        build = QtGui.QAction("Build", self)
        exit = QtGui.QAction("Quit", self)

        menu_bar = QtGui.QMenuBar()
        file = menu_bar.addMenu("&File")
        help = menu_bar.addMenu("&Help")

        file.addAction(open)
        file.addAction(save)
        file.addAction(build)
        file.addAction(exit)

        tab_widget = QtGui.QTabWidget()
        tab1 = QtGui.QWidget()
        tab2 = QtGui.QWidget()

        p1_vertical = QtGui.QVBoxLayout(tab1)
        p2_vertical = QtGui.QVBoxLayout(tab2)

        tab_widget.addTab(tab1, "Main")
        tab_widget.addTab(tab2, "Description")

        button1 = QtGui.QPushButton("button1")
        p1_vertical.addWidget(button1)

        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(menu_bar)
        vbox.addWidget(tab_widget)

        self.setLayout(vbox)

    def center(self):
        screen = QtGui.QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move((screen.width() - size.width()) / 2, (screen.height() - size.height()) / 2)


def main():
    app = QtGui.QApplication(sys.argv)
    frame = MainWindow()
    frame.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()