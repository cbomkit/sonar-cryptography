import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

salt = os.urandom(16)

# derive
kdf = Scrypt( # Noncompliant {{(PasswordBasedKeyDerivationFunction) scrypt}}
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
)

key = kdf.derive(b"my great password")