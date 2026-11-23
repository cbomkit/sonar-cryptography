from Crypto.PublicKey import RSA

def test_rsa():
    key1 = RSA.generate(bits=2048)                # Noncompliant {{(PrivateKey) RSA}}
    key2 = RSA.construct((2,3), True)             # Noncompliant {{(Key) RSA}}
    key3 = RSA.import_key("abcdef")               # Noncompliant {{(Key) RSA}}
