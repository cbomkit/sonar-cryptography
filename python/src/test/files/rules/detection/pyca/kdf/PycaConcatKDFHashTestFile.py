import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

otherinfo = b"concatkdf-example"

ckdf = ConcatKDFHash( # Noncompliant {{(KeyDerivationFunction) ConcatenationKDF}}
    algorithm=hashes.SHA256(),
    length=64,
    otherinfo=otherinfo,
)

key = ckdf.derive(b"input key")