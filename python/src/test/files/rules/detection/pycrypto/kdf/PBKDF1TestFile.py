from Crypto.Protocol.KDF import PBKDF1
from Crypto.Hash import SHA256

def test_pbkdf1():
    password = b"password"
    salt = b"salt1234"
    key = PBKDF1(password, salt, 16, SHA256) # Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF1-SHA-256}}
