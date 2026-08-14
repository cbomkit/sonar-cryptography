
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes    

key64 = b"01234567"
key128 = b"0123456789abcdef"
key192 = b"0123456789abcdef01234567"
key256 = b"0123456789abcdef0123456789abcdef"

iv = b"1234567890abcdef"
nonce = b"123456789012"
data = b"hello world!!!!!"

# AES-CBC (invalid 64-bit key — should fail at runtime, but useful for static detection testing)
algo_small = algorithms.AES(key64)
c_small = Cipher(algo_small, modes.CBC(iv)) # Noncompliant {{(BlockCipher) AES-CBC}}
encryptor_small = c_small.encryptor()
ct_small = encryptor_small.update(data) + encryptor_small.finalize()

# AES-CBC (128-bit)
algo_128 = algorithms.AES(key128)
c_128 = Cipher(algo_128, modes.CBC(iv)) # Noncompliant {{(BlockCipher) AES-CBC}}
encryptor_128 = c_128.encryptor()
ct_128 = encryptor_128.update(data) + encryptor_128.finalize()

# AES-CBC (192-bit)
algo_192 = algorithms.AES(key192)
c_192 = Cipher(algo_192, modes.CBC(iv)) # Noncompliant {{(BlockCipher) AES-CBC}}
encryptor_192 = c_192.encryptor()
ct_192 = encryptor_192.update(data) + encryptor_192.finalize()

# AES-CBC (256-bit)
algo_256 = algorithms.AES(key256)
c_256 = Cipher(algo_256, modes.CBC(iv)) # Noncompliant {{(BlockCipher) AES-CBC}}
encryptor_256 = c_256.encryptor()
ct_256 = encryptor_256.update(data) + encryptor_256.finalize()