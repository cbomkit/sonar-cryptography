from Crypto.Protocol.KDF import scrypt

def test_scrypt():
    password = b"password"
    salt = b"salt1234"
    key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1, num_keys=1) # Noncompliant {{(PasswordBasedKeyDerivationFunction) scrypt}}
