from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
#Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size= 2048
)
public_key = private_key.public_key()

#save private key to file
with open("private_key.pem" , "wb") as key_file:
    key_file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("public_key.pem" , "wb") as key_file:
    key_file.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))