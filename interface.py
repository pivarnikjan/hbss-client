import os, sys, json
from hashlib import sha512
from PyQt4 import QtGui, QtCore

import merkle
from utils import hbss_utills


class QuantumSignatureGUI(QtGui.QWidget):
    def __init__(self, parent=None):
        super(QuantumSignatureGUI, self).__init__(parent)
        self._init_ui()

    def _init_ui(self):
        self.setGeometry(0, 0, 300, 400)
        self.setWindowTitle("Quantum Subscriber")
        self.setWindowIcon(QtGui.QIcon("icon.png"))
        # self.resize(300, 400)
        self.setFixedSize(600, 400)
        # self.setMinimumSize(500, 650)
        self.center()
        self.set_layout()

    def menu(self):
        # --- Menu --- #
        synchronize = QtGui.QAction("Synchronize", self)
        logout = QtGui.QAction("Logout", self)
        exit = QtGui.QAction("Quit", self)

        menu_bar = QtGui.QMenuBar()
        file = menu_bar.addMenu("&File")
        help = menu_bar.addMenu("&Help")

        file.addAction(synchronize)
        file.addAction(logout)
        file.addAction(exit)
        return menu_bar

    def signature(self):
        tab1 = QtGui.QWidget()
        gridLayout = QtGui.QGridLayout(tab1)

        label_file = QtGui.QLabel("File to SIGN:")
        gridLayout.addWidget(label_file, 0, 0)

        self.textbox_file = QtGui.QLineEdit()
        gridLayout.addWidget(self.textbox_file, 0, 1)

        tab1.button_browse = QtGui.QPushButton("Browse", self)
        tab1.button_browse.clicked.connect(lambda: self.browse_click())
        gridLayout.addWidget(tab1.button_browse, 0, 4)
        # button_browse.clicked.connect(self.browse_click())

        gridLayout.addWidget(QtGui.QPushButton("Button 3"), 3, 4)
        gridLayout.addWidget(QtGui.QPushButton("Button 4"), 4, 4)
        gridLayout.addWidget(QtGui.QPushButton("Button 5"), 5, 4)

        return tab1

    def verification(self):
        tab2 = QtGui.QWidget()
        p2_vertical = QtGui.QVBoxLayout(tab2)
        return tab2

    def settings(self):
        tab3 = QtGui.QWidget()
        return tab3

    def tab_widgets(self):
        tab_widget = QtGui.QTabWidget()
        tab_widget.addTab(self.signature(), "Signature")
        tab_widget.addTab(self.verification(), "Verification")
        tab_widget.addTab(self.settings(), "Settings")
        return tab_widget

    def pokus(self):
        pass

    def set_layout(self):
        vbox = QtGui.QGridLayout()
        vbox.addWidget(self.menu())
        vbox.addWidget(self.tab_widgets())
        # vbox.addWidget(self.old)
        # typetablayout = QtGui.QGridLayout(vbox)

        self.setLayout(vbox)

    def browse_click(self):
        dlg = QtGui.QFileDialog()
        filename = QtGui.QFileDialog.getOpenFileName(dlg, 'Open File', '/')
        self.textbox_file.setText(filename)

    def sign_click(self):
        fname = self.fileTextbox.text()

        hashFromFile = hbss_utills.calculate_hash_from_file(open(fname, 'rb'), sha512())

        tree = merkle.MerkleTree(2, hash_function=("sha256", 256))

        mysig = tree.sign_message(hashFromFile)

        with open("signature.sig", mode='w') as SigOut:
            SigOut.write(json.dumps(mysig, indent=2))

        verify = tree.verify_message("signature.sig", hashFromFile)

        print(verify)

        finalMessage = QtGui.QMessageBox(self)
        finalMessage.information(self,
                                 "Message",
                                 "File was signed and signature was saved into \"signature.sig\"")

    def center(self):
        screen = QtGui.QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move((screen.width() - size.width()) / 2, (screen.height() - size.height()) / 2)


def main():
    app = QtGui.QApplication(sys.argv)
    frame = QuantumSignatureGUI()
    frame.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()