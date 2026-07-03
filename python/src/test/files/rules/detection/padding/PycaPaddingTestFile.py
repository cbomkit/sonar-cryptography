import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

key = os.urandom(32)
iv = os.urandom(16)
# Create a cipher object
cipher = Cipher(algorithms.CAST5(key), modes.CFB(iv)) # Noncompliant {{(BlockCipher) CAST5-CFB}}

padder = padding.ANSIX923(128).padder()
padded_data = padder.update(b"a secret message")
print(padded_data)
padded_data += padder.finalize()
print(padded_data)

# Then, one could use the cipher to encrypt the padded data