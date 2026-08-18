import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Salts should be randomly generated
salt = os.urandom(16)

# derive
kdf = PBKDF2HMAC( # Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2-SHA-256}}
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)

key = kdf.derive(b"my great password")