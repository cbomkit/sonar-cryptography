import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

data = b"a secret message"
aad = b"authenticated but unencrypted data"
key = AESGCM.generate_key(bit_length=128) # Noncompliant {{(SecretKey) AES}}
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, data, aad)
aesgcm.decrypt(nonce, ct, aad)