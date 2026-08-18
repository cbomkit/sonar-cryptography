from cryptography.hazmat.primitives import hashes

sha256_obj = hashes.Hash(hashes.SHA256()) # Noncompliant {{(MessageDigest) SHA-256}}
sha256_obj.update(b"data")
digest = sha256_obj.finalize()
