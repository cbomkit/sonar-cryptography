from Crypto.PublicKey import DSA

def test_dsa():
    key1 = DSA.generate(bits=2048)                # Noncompliant {{(PrivateKey) DSA}}
    key2 = DSA.construct((2,3), True)             # Noncompliant {{(Key) DSA}}
    key3 = DSA.import_key("abcdef")               # Noncompliant {{(Key) DSA}}
