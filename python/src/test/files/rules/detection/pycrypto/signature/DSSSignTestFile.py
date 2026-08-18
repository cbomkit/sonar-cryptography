from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

message = b'some message'
key = DSA.import_key(open('privkey.der').read())
h = SHA256.new(message)                              # Noncompliant {{(MessageDigest) SHA-256}}
signer = DSS.new(key, 'fips-186-3')                  # Noncompliant {{(Signature) DSA-SHA-256}}
signature = signer.sign(h)