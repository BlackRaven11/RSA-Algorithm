# RSA Key Generation
def generate_rsa_key_pair():
    # Select two prime numbers
    p = 17
    q = 19

    # Calculate modulus (N)
    modulus = p * q

    # Calculate Euler's totient function (phi)
    phi = (p - 1) * (q - 1)

    # Choose public exponent (e)
    e = 7

    # Calculate private exponent (d)
    d = 0
    while (d * e) % phi != 1:
        d += 1

    # Return public and private keys
    return (e, modulus), (d, modulus)


# RSA Encryption
def encrypt(message, public_key):
    e, modulus = public_key
    encrypted_message = [pow(ord(char), e, modulus) for char in message]
    return encrypted_message


# RSA Decryption
def decrypt(encrypted_message, private_key):
    d, modulus = private_key
    decrypted_message = [chr(pow(char, d, modulus)) for char in encrypted_message]
    return ''.join(decrypted_message)


# Example usage
message = "Hello, RSA!"
public_key, private_key = generate_rsa_key_pair()

encrypted_message = encrypt(message, public_key)
decrypted_message = decrypt(encrypted_message, private_key)

print("Original message:", message)
print("Encrypted message:", encrypted_message)
print("Decrypted message:", decrypted_message)