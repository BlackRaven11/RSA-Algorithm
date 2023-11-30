from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def decrypt_message(encrypted_message,private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    return decrypted_message.decode()

#Load private key from file
with open("private_key.pem" , "rb") as key_file:
    private_key =  serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=None
    )

#load encrypted message from file 
with open("encrypted_message.txt" , "rb") as file:
    encrypted_message = file.read()

#Decrypt the message
decrypted_message = decrypt_message(encrypted_message , private_key)

#print the decrypted message
print("Decrypted message: " , decrypted_message)