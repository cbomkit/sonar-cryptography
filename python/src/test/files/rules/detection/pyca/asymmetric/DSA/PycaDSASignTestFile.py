from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa

private_key = dsa.generate_private_key( # Noncompliant {{(PrivateKey) DSA}}
    key_size=1024,
)
data = b"this is some data I'd like to sign"
signature = private_key.sign(
    data,
    hashes.SHA256()
)