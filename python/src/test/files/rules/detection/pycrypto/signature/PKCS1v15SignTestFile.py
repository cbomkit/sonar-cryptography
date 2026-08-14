from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

message = b'To be signed'
key = RSA.import_key(open('private_key.der').read())
h = SHA256.new(message)                              # Noncompliant {{(MessageDigest) SHA-256}}
scheme = pkcs1_15.new(key)                           # Noncompliant {{(Signature) RSA-PKCS1-1.5-SHA-256}}
signature = scheme.sign(h)