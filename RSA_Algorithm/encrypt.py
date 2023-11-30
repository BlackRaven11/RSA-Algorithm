#Adding Libraries
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes

def encrypt_message(message , public_key): #encrypting the message using public key
    encrypted_message = public_key.encrypt(
        message.encode(), #the encode() is converting the message into bytes
        #the OAEP : Optimal Asymmtric Encryption Padding is to perform the encryption by scheme
        #which provides probabilistic encryption and enhances security
        padding.OAEP(  
            #to configure the OAEP padding. we use SHA256 to hashing(more info --> info.txt)         
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None #its optional and we don't need it so we set it as None
        )
    )
    return encrypted_message

#load public key from file
with open("public_key.pem","rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=None
    )

#prompt user for message to encrypt
plaintext = input("Enter the message to encrypt: ")


