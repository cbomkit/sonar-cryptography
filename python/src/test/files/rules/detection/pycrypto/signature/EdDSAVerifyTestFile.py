from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA512

signature = b'some signature'
raw_public_bytes = b"\x01" * 32
public_key = eddsa.import_public_key(raw_public_bytes)
verifier = eddsa.new(public_key, 'rfc8032')                       # Noncompliant {{(Signature) EdDSA}}

try:
    verifier.verify(h, signature)
    print("The message is authentic")
except ValueError:
    print("The message is not authentic")