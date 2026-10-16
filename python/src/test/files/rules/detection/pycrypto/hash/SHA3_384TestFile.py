from Crypto.Hash import SHA3_384

hash_sha3_384 = SHA3_384.new() # Noncompliant {{(MessageDigest) SHA3-384}}
