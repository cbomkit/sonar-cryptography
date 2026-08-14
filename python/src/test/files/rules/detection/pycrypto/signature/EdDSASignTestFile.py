from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA512

message = b'some message'
prehashed_message = SHA512.new(message)                     # Noncompliant {{(MessageDigest) SHA-512}}
key = ECC.import_key(open("private_ed25519.pem").read())
signer = eddsa.new(key, 'rfc8032')                          # Noncompliant {{(Signature) EdDSA}}
signature = signer.sign(prehashed_message)