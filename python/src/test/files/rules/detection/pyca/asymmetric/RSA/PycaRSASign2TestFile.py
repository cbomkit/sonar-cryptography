from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils

private_key = rsa.generate_private_key( # Noncompliant {{(PrivateKey) RSA}}
    public_exponent=65537,
    key_size=2048,
)

message = b"A message I want to sign"
signature = private_key.sign(
    message,
    padding.PKCS1v15(),
    hashes.SHA3_384()
)
