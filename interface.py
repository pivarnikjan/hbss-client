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
        sublayout = QtGui.QVBoxLayout()

        label_login = QtGui.QLabel("Username")
        sublayout.addWidget(label_login)
        sublayout.addWidget(self.textbox_login)

        label_password = QtGui.QLabel("Password")
        sublayout.addWidget(label_password)
        self.textbox_password.setEchoMode(self.textbox_password.Password)
        sublayout.addWidget(self.textbox_password)

        sublayout_horizontal = QtGui.QHBoxLayout()
        button_login = QtGui.QPushButton("Login", self)
        button_login.clicked.connect(self.handle_login)

        sublayout_horizontal.addWidget(button_login)
        button_register = QtGui.QPushButton("Register", self)
        button_register.clicked.connect(self.handle_register)

        sublayout_horizontal.addWidget(button_register)
        layout.addLayout(sublayout, 0, 0)
        layout.addLayout(sublayout_horizontal, 1, 0)

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

        label_file = QtGui.QLabel("File to VERIFY:")
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

    def settings_layout(self):
        tab3 = QtGui.QWidget()
        grid_layout = QtGui.QGridLayout(tab3)

        sub_layout_top = QtGui.QVBoxLayout()
        hash_function_group = QtGui.QButtonGroup()
        label_for_hash_fn = QtGui.QLabel("Select hash function:")
        sub_layout_top.addWidget(label_for_hash_fn)

        q_button_sha256 = QtGui.QRadioButton("sha256")
        q_button_sha256.toggled.connect(lambda: self.button_state_hash(q_button_sha256))
        hash_function_group.addButton(q_button_sha256)
        sub_layout_top.addWidget(q_button_sha256)

        q_button_sha384 = QtGui.QRadioButton("sha384")
        q_button_sha384.toggled.connect(lambda: self.button_state_hash(q_button_sha384))
        hash_function_group.addButton(q_button_sha384)
        sub_layout_top.addWidget(q_button_sha384)

        q_button_sha512 = QtGui.QRadioButton("sha512")
        q_button_sha512.toggled.connect(lambda: self.button_state_hash(q_button_sha512))
        hash_function_group.addButton(q_button_sha512)
        # q_button_sha512.setChecked(True)
        sub_layout_top.addWidget(q_button_sha512)

        sub_layout_bottom = QtGui.QVBoxLayout()
        prng_group = QtGui.QButtonGroup()
        label_for_random_function = QtGui.QLabel("Select PRNG:")
        sub_layout_bottom.addWidget(label_for_random_function)

        q_button_ssl_rng = QtGui.QRadioButton("SSL")
        # q_button_ssl_rng.setChecked(True)
        q_button_ssl_rng.toggled.connect(lambda: self.button_state_prng(q_button_ssl_rng))
        prng_group.addButton(q_button_ssl_rng)
        sub_layout_bottom.addWidget(q_button_ssl_rng)

        q_button_ssl_crypto = QtGui.QRadioButton("Crypto")
        q_button_ssl_crypto.toggled.connect(lambda: self.button_state_prng(q_button_ssl_crypto))
        prng_group.addButton(q_button_ssl_crypto)
        sub_layout_bottom.addWidget(q_button_ssl_crypto)

        sub_layout_right = QtGui.QVBoxLayout()
        label_for_signature_file = QtGui.QLabel("Signature filename:")
        sub_layout_right.addWidget(label_for_signature_file)
        tab3.textbox_for_signature = QtGui.QLineEdit()
        sub_layout_right.addWidget(tab3.textbox_for_signature)

        label_for_merkle_tree_height = QtGui.QLabel("Merkle tree height:")
        sub_layout_right.addWidget(label_for_merkle_tree_height)
        tab3.spinner_for_height = QtGui.QSpinBox()
        tab3.spinner_for_height.setValue(2)
        tab3.spinner_for_height.setMaximum(20)
        sub_layout_right.addWidget(tab3.spinner_for_height)

        button_apply_changes = QtGui.QPushButton("Apply changes")
        button_apply_changes.clicked.connect(lambda: self.apply_changes(tab3))

        grid_layout.addLayout(sub_layout_top, 0, 0)
        grid_layout.addLayout(sub_layout_right, 0, 2)
        grid_layout.addLayout(sub_layout_bottom, 1, 0)
        grid_layout.addWidget(button_apply_changes, 3, 3)

        return tab3

    @staticmethod
    def apply_changes(tab):
        config.SIGNATURE_FILENAME = tab.textbox_for_signature
        config.MERKLE_TREE_HEIGHT = tab.spinner_for_height

    @staticmethod
    def button_state_prng(radio_button):
        config.PRNG = radio_button.text()

    @staticmethod
    def button_state_hash(radio_button):
        config.HASH_FUNCTION = radio_button.text()

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
    # login = Login()
    #
    # if login.exec_() == QtGui.QDialog.Accepted:
    window = QuantumSignatureGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
