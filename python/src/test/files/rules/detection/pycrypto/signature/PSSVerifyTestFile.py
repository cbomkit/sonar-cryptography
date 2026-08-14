from Crypto.Signature import pss
from Crypto.Signature.pss import PSS_SigScheme
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

message = b'To be signed'
key = RSA.import_key(open('pubkey.der', 'rb').read())
h = SHA256.new(message)                               # Noncompliant {{(MessageDigest) SHA-256}}
verifier = pss.new(key)                               # Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
signature = b'some sginature'

try:
    verifier.verify(h, signature)
    print("The signature is authentic.")
except (ValueError):
    print("The signature is not authentic.")