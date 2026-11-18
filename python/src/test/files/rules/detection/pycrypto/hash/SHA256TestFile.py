from Crypto.Hash import SHA256

hash_sha256 = SHA256.new() # Noncompliant {{(MessageDigest) SHA-256}}
