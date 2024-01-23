import sys
from PyQt5.QtWidgets import QApplication, QDialog, QLabel, QTextEdit, QVBoxLayout, QPushButton, QMessageBox
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class EncryptionWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Encryption")
        self.setGeometry(100, 100, 400, 200)

        self.public_key_label = QLabel("Public Key:")
        self.public_key_text_edit = QTextEdit()

        self.plain_text_label = QLabel("Plain Text:")
        self.plain_text_text_edit = QTextEdit()

        self.encrypted_text_label = QLabel("Encrypted Text:")
        self.encrypted_text_text_edit = QTextEdit()
        self.encrypted_text_text_edit.setReadOnly(True)

        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.clicked.connect(self.encrypt_text)

        self.copy_encrypted_button = QPushButton("Copy Encrypted Text")
        self.copy_encrypted_button.clicked.connect(self.copy_encrypted_text)

        vbox = QVBoxLayout()
        vbox.addWidget(self.public_key_label)
        vbox.addWidget(self.public_key_text_edit)
        vbox.addWidget(self.plain_text_label)
        vbox.addWidget(self.plain_text_text_edit)
        vbox.addWidget(self.encrypted_text_label)
        vbox.addWidget(self.encrypted_text_text_edit)
        vbox.addWidget(self.copy_encrypted_button)
        vbox.addWidget(self.encrypt_button)

        self.setLayout(vbox)

    def encrypt_text(self):
        public_key_pem = self.public_key_text_edit.toPlainText().encode()
        plain_text = self.plain_text_text_edit.toPlainText().encode()

        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            encrypted_text = public_key.encrypt(
                plain_text,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.encrypted_text_text_edit.setPlainText(encrypted_text.hex())
        except (ValueError, TypeError):
            QMessageBox.warning(self, "Error", "Invalid public key.")

    def copy_encrypted_text(self):
        encrypted_text = self.encrypted_text_text_edit.toPlainText()
        if encrypted_text:
            QApplication.clipboard().setText(encrypted_text)
            QMessageBox.information(self, "Encrypted Text Copied", "Encrypted Text copied to clipboard.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = EncryptionWindow()
    window.show()
    sys.exit(app.exec_())