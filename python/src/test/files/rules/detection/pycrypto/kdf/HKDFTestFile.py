from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512

def test_hkdf():
    secret = b"secret"
    salt = b"salt1234567890ab"
    key = HKDF(master=secret, key_len=32, salt=salt, hashmod=SHA512) # Noncompliant {{(KeyDerivationFunction) HKDF-SHA-512}}
