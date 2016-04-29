import json
import sys
from hashlib import sha512

from PyQt4 import QtGui

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
        self.setFixedSize(600, 400)
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

    def signature_layout(self):
        tab1 = QtGui.QWidget()
        grid_layout = QtGui.QGridLayout(tab1)

        label_file = QtGui.QLabel("File to SIGN:")
        grid_layout.addWidget(label_file, 0, 0)

        # noinspection PyAttributeOutsideInit
        textbox_file = QtGui.QLineEdit()
        grid_layout.addWidget(textbox_file, 0, 1)

        tab1.button_browse = QtGui.QPushButton("Browse", self)
        tab1.button_browse.clicked.connect(lambda: self.browse_click(textbox_file))
        grid_layout.addWidget(tab1.button_browse, 0, 3)

        tab1.button_sign = QtGui.QPushButton("Sign", self)
        tab1.button_sign.clicked.connect(lambda: self.sign_click(textbox_file))
        grid_layout.addWidget(tab1.button_sign, 1, 3)

        return tab1

    def verification_layout(self):
        tab2 = QtGui.QWidget()
        grid_layout = QtGui.QGridLayout(tab2)

        label_file = QtGui.QLabel("File to SIGN:")
        grid_layout.addWidget(label_file, 0, 0)
        label_signature = QtGui.QLabel("Signature:")
        grid_layout.addWidget(label_signature, 1, 0)

        # noinspection PyAttributeOutsideInit
        textbox_file = QtGui.QLineEdit()
        grid_layout.addWidget(textbox_file, 0, 1)
        textbox_signature = QtGui.QLineEdit()
        grid_layout.addWidget(textbox_signature, 1, 1)

        tab2.button_browse = QtGui.QPushButton("Browse", self)
        tab2.button_browse.clicked.connect(lambda: self.browse_click(textbox_file))
        grid_layout.addWidget(tab2.button_browse, 0, 3)
        tab2.button_browse = QtGui.QPushButton("Browse", self)
        tab2.button_browse.clicked.connect(lambda: self.browse_click(textbox_signature))
        grid_layout.addWidget(tab2.button_browse, 1, 3)

        tab2.button_verify = QtGui.QPushButton("Verify", self)
        tab2.button_verify.clicked.connect(lambda: self.verify_click(textbox_file, textbox_signature))
        grid_layout.addWidget(tab2.button_verify, 2, 3)

        return tab2

    @staticmethod
    def settings_layout():
        tab3 = QtGui.QWidget()
        return tab3

    def tab_widgets(self):
        tab_widget = QtGui.QTabWidget()
        tab_widget.addTab(self.signature_layout(), "Signature")
        tab_widget.addTab(self.verification_layout(), "Verification")
        tab_widget.addTab(self.settings_layout(), "Settings")
        return tab_widget

    def set_layout(self):
        vbox = QtGui.QGridLayout()
        vbox.addWidget(self.menu())
        vbox.addWidget(self.tab_widgets())
        self.setLayout(vbox)

    @staticmethod
    def browse_click(textbox_file):
        dlg = QtGui.QFileDialog()
        filename = QtGui.QFileDialog.getOpenFileName(dlg, 'Open File', '/')
        textbox_file.setText(filename)

    def sign_click(self, textbox_file):
        fname = textbox_file.text()

        hash_from_file = hbss_utills.calculate_hash_from_file(open(fname, 'rb'), sha512())

        tree = merkle.MerkleTree(2, hash_function=("sha256", 256))

        mysig = tree.sign_message(hash_from_file)

        with open("signature.sig", mode='w') as SigOut:
            SigOut.write(json.dumps(mysig, indent=2))

        verify = tree.verify_message("signature.sig", hash_from_file)

        print(verify)

        final_message = QtGui.QMessageBox(self)
        final_message.information(self,
                                  "Message",
                                  "File was signed and signature was saved into \"signature.sig\"")

    def verify_click(self, textbox_file, textbox_signature):
        pass

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
