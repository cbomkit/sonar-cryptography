import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

data = b"a secret message"
aad = b"authenticated but unencrypted data"
key = ChaCha20Poly1305.generate_key() # Noncompliant {{(SecretKey) ChaCha20}}
chacha = ChaCha20Poly1305(key)
nonce = os.urandom(12)
ct = chacha.encrypt(nonce, data, aad)
nonce2 = os.urandom(12)
chacha.decrypt(nonce2, ct, aad)