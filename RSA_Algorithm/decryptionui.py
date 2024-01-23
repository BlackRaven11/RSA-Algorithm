import sys
from PyQt5.QtWidgets import QApplication, QDialog, QLabel, QTextEdit, QVBoxLayout, QPushButton, QMessageBox
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

class DecryptionWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Decryption")
        self.setGeometry(100, 100, 400, 200)

        self.encrypted_text_label = QLabel("Encrypted Text:")
        self.encrypted_text_text_edit = QTextEdit()

        self.private_key_label = QLabel("Private Key:")
        self.private_key_text_edit = QTextEdit()

        self.decrypted_text_label = QLabel("Decrypted Text:")
        self.decrypted_text_text_edit = QTextEdit()
        self.decrypted_text_text_edit.setReadOnly(True)

        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.clicked.connect(self.decrypt_text)

        vbox = QVBoxLayout()
        vbox.addWidget(self.encrypted_text_label)
        vbox.addWidget(self.encrypted_text_text_edit)
        vbox.addWidget(self.private_key_label)
        vbox.addWidget(self.private_key_text_edit)
        vbox.addWidget(self.decrypted_text_label)
        vbox.addWidget(self.decrypted_text_text_edit)
        vbox.addWidget(self.decrypt_button)

        self.setLayout(vbox)

    def decrypt_text(self):
        encrypted_text_hex = self.encrypted_text_text_edit.toPlainText()
        private_key_pem = self.private_key_text_edit.toPlainText().encode()

        try:
            private_key = serialization.load_pem_private_key(private_key_pem, password=None)
            encrypted_text = bytes.fromhex(encrypted_text_hex)
            padding_algorithm = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
            decrypted_text = private_key.decrypt(encrypted_text, padding_algorithm)
            self.decrypted_text_text_edit.setPlainText(decrypted_text.decode())
        except Exception as e:
            QMessageBox.warning(self, "Error", "Decryption failed. Error: {}".format(str(e)))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DecryptionWindow()
    window.show()
    sys.exit(app.exec_())