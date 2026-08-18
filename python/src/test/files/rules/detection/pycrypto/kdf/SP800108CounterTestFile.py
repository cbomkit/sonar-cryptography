from Crypto.Protocol.KDF import SP800_108_Counter
from Crypto.Hash import HMAC, SHA256

def prf(s, x):
    return HMAC.new(s, x, SHA256).digest()   # NonCompliant {{(Mac) HMAC-SHA-256}}

def test_sp800_108_counter():
    secret = b"secret"
    key = SP800_108_Counter(secret, 16, prf) # Noncompliant {{(KeyDerivationFunction) SP800_108_CounterKDF}}
