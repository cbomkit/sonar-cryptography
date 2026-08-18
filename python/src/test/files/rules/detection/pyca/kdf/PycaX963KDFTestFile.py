import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

sharedinfo = b"ANSI-KDF-X9.63 Example"

xkdf = X963KDF( # Noncompliant {{(KeyDerivationFunction) ANSI-KDF-X9.63}}
    algorithm=hashes.SHA256(),
    length=32,
    sharedinfo=sharedinfo,
)

key = xkdf.derive(b"input key")