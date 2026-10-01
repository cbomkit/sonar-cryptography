from Crypto.Hash import SHA3_512

hash_sha3_512 = SHA3_512.new() # Noncompliant {{(MessageDigest) SHA3-512}}
