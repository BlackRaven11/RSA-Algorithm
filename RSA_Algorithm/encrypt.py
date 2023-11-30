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
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message