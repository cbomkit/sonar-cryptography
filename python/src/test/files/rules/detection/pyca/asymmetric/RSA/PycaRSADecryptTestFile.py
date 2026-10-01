from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

private_key = rsa.generate_private_key( # Noncompliant {{(PrivateKey) RSA}}
    public_exponent=65537,
    key_size=1024,
)

def decrypt(ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA384()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext