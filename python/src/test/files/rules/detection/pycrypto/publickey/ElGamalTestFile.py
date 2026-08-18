from Crypto.PublicKey import ElGamal

def test_elgamal():
    key1 = ElGamal.generate(2048, None)           # Noncompliant {{(PrivateKey) ElGamal}}
    key2 = ElGamal.construct((2,3,4))             # Noncompliant {{(Key) ElGamal}}
