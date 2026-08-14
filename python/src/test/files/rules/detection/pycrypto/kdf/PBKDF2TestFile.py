from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

def test_pbkdf2():
    password = b"password"
    salt = b"salt1234"
    key = PBKDF2(password, salt, dkLen=64, count=1000, hmac_hash_module=SHA512) # Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2-SHA-512}}
