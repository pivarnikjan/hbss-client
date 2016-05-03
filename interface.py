import json
import sys
from hashlib import sha512

from PyQt4 import QtGui
from PyQt4 import QtCore

import merkle
import config
from utils import hbss_utills


class Login(QtGui.QDialog):
    def __init__(self, parent=None):
        super(Login, self).__init__(parent)
        self.textbox_password = QtGui.QLineEdit()
        self.textbox_login = QtGui.QLineEdit()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Login")
        self.set_layout()

    def set_layout(self):
        layout = QtGui.QGridLayout(self)

        label_login = QtGui.QLabel("Username")
        label_password = QtGui.QLabel("Password")
        self.textbox_password.setEchoMode(self.textbox_password.Password)
        button_login = QtGui.QPushButton("Login", self)
        button_register = QtGui.QPushButton("Register", self)

        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(label_login)
        vbox.addWidget(self.textbox_login)
        vbox.addWidget(label_password)
        vbox.addWidget(self.textbox_password)

        hbox = QtGui.QHBoxLayout()
        hbox.addWidget(button_login)
        hbox.addWidget(button_register)

        button_login.clicked.connect(self.handle_login)
        button_register.clicked.connect(self.handle_register)

        layout.addLayout(vbox, 0, 0)
        layout.addLayout(hbox, 1, 0)
        # self.set_layout(layout)

    def handle_login(self):
        if (self.textbox_login.text() == 'foo' and
                    self.textbox_password.text() == 'bar'):
            self.accept()
        else:
            QtGui.QMessageBox.warning(
                self, 'Error', 'Bad user or password')

    @staticmethod
    def handle_register():
        QtGui.QDesktopServices.openUrl(QtCore.QUrl("http://127.0.0.1:5000/"))


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

        label_file = QtGui.QLabel("File to SIGN:")
        textbox_file = QtGui.QLineEdit()
        tab1.button_browse = QtGui.QPushButton("Browse", self)
        tab1.button_sign = QtGui.QPushButton("Sign", self)

        grid_layout = QtGui.QGridLayout(tab1)
        grid_layout.addWidget(label_file, 0, 0)
        grid_layout.addWidget(textbox_file, 0, 1)
        grid_layout.addWidget(tab1.button_browse, 0, 3)
        grid_layout.addWidget(tab1.button_sign, 1, 3)

        tab1.button_browse.clicked.connect(lambda: self.browse_click(textbox_file))
        tab1.button_sign.clicked.connect(lambda: self.sign_click(textbox_file))

        return tab1

    def verification_layout(self):
        tab2 = QtGui.QWidget()

        label_file = QtGui.QLabel("File to VERIFY:")
        label_signature = QtGui.QLabel("Signature:")
        textbox_file = QtGui.QLineEdit()
        textbox_signature = QtGui.QLineEdit()
        tab2.button_browse_file = QtGui.QPushButton("Browse", self)
        tab2.button_browse_signature = QtGui.QPushButton("Browse", self)
        tab2.button_verify = QtGui.QPushButton("Verify", self)

        grid_layout = QtGui.QGridLayout(tab2)
        grid_layout.addWidget(label_file, 0, 0)
        grid_layout.addWidget(label_signature, 1, 0)
        grid_layout.addWidget(textbox_file, 0, 1)
        grid_layout.addWidget(textbox_signature, 1, 1)
        grid_layout.addWidget(tab2.button_browse_file, 0, 3)
        grid_layout.addWidget(tab2.button_browse_signature, 1, 3)
        grid_layout.addWidget(tab2.button_verify, 2, 3)

        tab2.button_browse_file.clicked.connect(lambda: self.browse_click(textbox_file))
        tab2.button_browse_signature.clicked.connect(lambda: self.browse_click(textbox_signature))
        tab2.button_verify.clicked.connect(lambda: self.verify_click(textbox_file, textbox_signature))

        return tab2

    def settings_hash_function(self):
        group_box = QtGui.QGroupBox("Select hash function")

        radio1 = QtGui.QRadioButton("sha256")
        radio2 = QtGui.QRadioButton("sha384")
        radio3 = QtGui.QRadioButton("sha512")

        radio1.toggled.connect(lambda: self.button_state(radio1))
        radio2.toggled.connect(lambda: self.button_state(radio2))
        radio3.toggled.connect(lambda: self.button_state(radio3))

        radio1.setChecked(True)

        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(radio1)
        vbox.addWidget(radio2)
        vbox.addWidget(radio3)
        vbox.addStretch(1)
        group_box.setLayout(vbox)

        return group_box

    def settings_prng(self):
        group_box = QtGui.QGroupBox("Select PRNG:")

        radio1 = QtGui.QRadioButton("SSL")
        radio2 = QtGui.QRadioButton("Crypto")

        radio1.toggled.connect(lambda: self.button_state(radio1))
        radio2.toggled.connect(lambda: self.button_state(radio2))

        radio1.setChecked(True)

        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(radio1)
        vbox.addWidget(radio2)
        vbox.addStretch(1)
        group_box.setLayout(vbox)

        return group_box

    @staticmethod
    def settings_filename(tab):
        group_box = QtGui.QGroupBox()

        label_for_signature_file = QtGui.QLabel("Signature filename:")
        tab.textbox_for_signature = QtGui.QLineEdit()

        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(label_for_signature_file)
        vbox.addWidget(tab.textbox_for_signature)
        group_box.setLayout(vbox)

        return group_box

    @staticmethod
    def settings_tree_height(tab):
        group_box = QtGui.QGroupBox()

        label_for_tree_height = QtGui.QLabel("Merkle tree height:")
        tab.spinner_for_height = QtGui.QSpinBox()

        tab.spinner_for_height.setValue(2)
        tab.spinner_for_height.setMaximum(20)

        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(label_for_tree_height)
        vbox.addWidget(tab.spinner_for_height)
        group_box.setLayout(vbox)

        return group_box

    def settings_layout(self):
        tab3 = QtGui.QWidget()

        button_apply_changes = QtGui.QPushButton("Apply changes")
        tmp = button_apply_changes.clicked.connect(lambda: self.apply_changes(tab3))

        grid_layout = QtGui.QGridLayout(tab3)
        grid_layout.addWidget(self.settings_hash_function(), 0, 0)
        grid_layout.addWidget(self.settings_filename(tab3), 0, 2)
        grid_layout.addWidget(self.settings_prng(), 1, 0)
        grid_layout.addWidget(self.settings_tree_height(tab3), 1, 2)
        grid_layout.addWidget(button_apply_changes, 3, 3)

        return tab3

    @staticmethod
    def apply_changes(tab):
        config.SIGNATURE_FILENAME = tab.textbox_for_signature
        # print(tab.textbox_for_signature)
        config.MERKLE_TREE_HEIGHT = tab.spinner_for_height

    @staticmethod
    def button_state(radio_button):
        return radio_button.text()

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
        tree = merkle.MerkleTree(config.MERKLE_TREE_HEIGHT,
                                 PRNG=config.PRNG,
                                 hash_function=(config.HASH_FUNCTION, config.HASH_FUNCTION_LENGTH))
        mysig = tree.sign_message(hash_from_file)

        with open(config.SIGNATURE_FILENAME, mode='w') as SigOut:
            SigOut.write(json.dumps(mysig, indent=2))

        verify = tree.verify_message("signature.sig", hash_from_file)
        print(verify)

        data = tree.export_tree()
        with open('merkle_tree.json', 'w') as f:
            f.write(json.dumps(data, f, indent=2))

        final_message = QtGui.QMessageBox(self)
        final_message.information(self,
                                  "Message",
                                  "File was signed and signature was saved into %s" % config.SIGNATURE_FILENAME)

    def verify_click(self, textbox_file, textbox_signature):
        print(textbox_file.text(), textbox_signature.text())
        hash_from_file = hbss_utills.calculate_hash_from_file(open(textbox_file.text(), 'rb'), sha512())
        tree = merkle.MerkleTree(existing_tree="merkle_tree.json")
        verify = tree.verify_message(textbox_signature.text(), hash_from_file)

        verify_message = QtGui.QMessageBox(self)
        if verify:
            verify_message.information(self,
                                       "Message",
                                       "Successful verification")
        else:
            verify_message.warning(self,
                                   "Message",
                                   "Verification failed")

    def center(self):
        screen = QtGui.QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move((screen.width() - size.width()) / 2, (screen.height() - size.height()) / 2)


def main():
    app = QtGui.QApplication(sys.argv)
    login = Login()

    if login.exec_() == QtGui.QDialog.Accepted:
        window = QuantumSignatureGUI()
        window.show()
        sys.exit(app.exec_())


if __name__ == '__main__':
    main()
