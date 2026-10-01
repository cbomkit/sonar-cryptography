from Crypto.Hash import SHA3_256

hash_sha3_256 = SHA3_256.new() # Noncompliant {{(MessageDigest) SHA3-256}}
