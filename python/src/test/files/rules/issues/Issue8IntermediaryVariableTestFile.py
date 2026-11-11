from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"\x00" * 32
iv = b"\x00" * 16

# intermediary variable: alg -> algorithms.AES(key)
alg = algorithms.AES(key)
intermediary = alg
cipher = Cipher(intermediary, modes.CBC(iv))  # Noncompliant
