from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

def test_pbkdf2_positional():
    password = b"password"
    salt = b"salt1234"
    # prf=None (unset, so not mutually exclusive) occupies positional slot 4; hmac_hash_module is slot 5
    key = PBKDF2(password, salt, 64, 1000, None, SHA512) # Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2-SHA-512}}
