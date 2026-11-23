import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC

salt = os.urandom(16)
otherinfo = b"concatkdf-example"

ckdf = ConcatKDFHMAC( # Noncompliant {{(KeyDerivationFunction) ConcatenationKDF}}
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    otherinfo=otherinfo,
)

key = ckdf.derive(b"input key")