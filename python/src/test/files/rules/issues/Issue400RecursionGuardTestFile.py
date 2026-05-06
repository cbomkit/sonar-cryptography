from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"\x00" * 32
iv = b"\x00" * 16

# Mutual assignment cycle: tracing alg reaches intermediary, which traces back to alg.
# Without a visited-set guard in traceSymbol this causes infinite recursion.
alg = algorithms.AES(key)
intermediary = alg
alg = intermediary  # cycle: alg -> intermediary -> alg -> ...
cipher = Cipher(alg, modes.CBC(iv))  # Noncompliant
