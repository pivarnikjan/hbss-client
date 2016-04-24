import base64
import json
import sys
from hashlib import sha512

from PyQt4.QtGui import *

import merkle
from utils import hbss_utills


class QuantumSignatureGUI(QMainWindow):
    width = 380
    height = 200
    
    def __init__(self, parent=None):
        super(QuantumSignatureGUI, self).__init__(parent)
        self.init_ui()

    def init_ui(self):
        self.setFixedSize(self.width, self.height)
        self.setWindowTitle("Quantum Subscriber")

        # Sign label
        userLabel = QLabel(self)
        userLabel.move(20, 15)
        userLabel.setText('File to SIGN:')
        # Sign textbox
        self.fileTextbox = QLineEdit(self)
        self.fileTextbox.move(20, 45)
        self.fileTextbox.resize(self.width - 40, 20)
        # Browse button
        buttonBrowse = QPushButton('Browse', self)
        buttonBrowse.move(20, 100)
        buttonBrowse.clicked.connect(self.browse_click)
        # Sign button
        buttonSign = QPushButton('Sign', self)
        buttonSign.move(260, 100)
        buttonSign.clicked.connect(self.sign_click)

    def browse_click(self):
        filename = QFileDialog.getOpenFileName(self, 'Open File', '/')
        self.fileTextbox.setText(filename)

    def sign_click(self):
        fname = self.fileTextbox.text()

        hashFromFile = hbss_utills.calculate_hash_from_file(open(fname, 'rb'), sha512())

        tree = merkle.MerkleTree(2)
        key = tree.select_unused_key(mark_used=True, force=False)

        mysig = tree._sign_message(key, hashFromFile)

        with open("signature.sig", mode='w') as SigOut:
            SigOut.write(json.dumps(mysig, indent=2))

        verify = tree.verify_message(key, "signature.sig", hashFromFile)
        print(verify)

        finalMessage = QMessageBox(self)
        finalMessage.information(self,
                                     "Message",
                                     "File was signed and signature was saved into \"signature.sig\"")
        # print("Sprava bola podpisana")


def main():
    app = QApplication(sys.argv)
    myApp = QuantumSignatureGUI()
    myApp.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
