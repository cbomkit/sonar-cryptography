from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

message = b'To be signed'
key = RSA.import_key(open('private_key.der').read())
h = SHA256.new(message)                              # Noncompliant {{(MessageDigest) SHA-256}}
scheme = pss.new(key)                                # Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
signature = scheme.sign(h)