from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
#Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent = 65537
    key_size= 2048
)
