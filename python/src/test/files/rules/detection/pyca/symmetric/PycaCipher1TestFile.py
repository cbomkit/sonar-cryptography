import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

key = os.urandom(32)
iv = os.urandom(16)
# Create a cipher object
cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) # Noncompliant {{(BlockCipher) AES-CBC-PKCS7}}

# Specify padding (PKCS7 in this case)
padder = PKCS7(algorithms.AES.block_size).padder()

# Encrypt
encryptor = cipher.encryptor()
padded_data = padder.update(b"a secret message") + padder.finalize()
ct = encryptor.update(padded_data) + encryptor.finalize()

# Decrypt
decryptor = cipher.decryptor()
padded_res = decryptor.update(ct) + decryptor.finalize()
unpadded_res = padder.update(padded_res) + padder.finalize()