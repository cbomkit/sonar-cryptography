import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

key = os.urandom(32)
iv = os.urandom(16)
# Create a cipher object
cipher = Cipher(algorithms.Camellia(key), modes.OFB(iv)) # Noncompliant {{(BlockCipher) CAMELLIA-OFB}}

# Encrypt
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()
