import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(32)
iv = os.urandom(16)
# Create a cipher object
cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None) # Noncompliant {{(StreamCipher) ChaCha20}}

# Encrypt
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()
