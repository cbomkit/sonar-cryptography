from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

key = RSA.import_key(open('public.pem').read())
cipher = PKCS1_OAEP.new(key, SHA256)  # Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}
