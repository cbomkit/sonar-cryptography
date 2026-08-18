from Crypto.PublicKey import ECC

def test_ecc():
    key1 = ECC.generate(curve="Ed25519")                   # Noncompliant {{(PrivateKey) EC-Edwards25519}}
    key2 = ECC.construct(curve="Curve448", seed=b"A" * 56) # Noncompliant {{(Key) EC-Curve448}}
    key3 = ECC.import_key("abcdef")                        # Noncompliant {{(Key) EC}}
