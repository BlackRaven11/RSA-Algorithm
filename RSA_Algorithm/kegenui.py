import sys
from PyQt5.QtWidgets import QApplication, QDialog, QLabel, QTextEdit, QVBoxLayout, QPushButton, QMessageBox
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class KeyGenerationWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Key Generation")
        self.setGeometry(100, 100, 400, 200)

        self.private_key_label = QLabel("Private Key:")
        self.private_key_text_edit = QTextEdit()
        self.private_key_text_edit.setReadOnly(True)

        self.public_key_label = QLabel("Public Key:")
        self.public_key_text_edit = QTextEdit()
        self.public_key_text_edit.setReadOnly(True)

        self.generate_button = QPushButton("Generate Keys")
        self.generate_button.clicked.connect(self.generate_keys)

        self.copy_private_key_button = QPushButton("Copy Private Key")
        self.copy_private_key_button.clicked.connect(self.copy_private_key)

        self.copy_public_key_button = QPushButton("Copy Public Key")
        self.copy_public_key_button.clicked.connect(self.copy_public_key)

        vbox = QVBoxLayout()
        vbox.addWidget(self.private_key_label)
        vbox.addWidget(self.private_key_text_edit)
        vbox.addWidget(self.copy_private_key_button)
        vbox.addWidget(self.public_key_label)
        vbox.addWidget(self.public_key_text_edit)
        vbox.addWidget(self.copy_public_key_button)
        vbox.addWidget(self.generate_button)

        self.setLayout(vbox)

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.private_key_text_edit.setPlainText(private_pem.decode())
        self.public_key_text_edit.setPlainText(public_pem.decode())

    def copy_private_key(self):
        private_key = self.private_key_text_edit.toPlainText()
        if private_key:
            QApplication.clipboard().setText(private_key)
            QMessageBox.information(self, "Private Key Copied", "Private Key copied to clipboard.")

    def copy_public_key(self):
        public_key = self.public_key_text_edit.toPlainText()
        if public_key:
            QApplication.clipboard().setText(public_key)
            QMessageBox.information(self, "Public Key Copied", "Public Key copied to clipboard.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = KeyGenerationWindow()
    window.show()
    sys.exit(app.exec_())