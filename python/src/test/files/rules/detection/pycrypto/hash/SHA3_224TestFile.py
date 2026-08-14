from Crypto.Hash import SHA3_224

hash_sha3_224 = SHA3_224.new() # Noncompliant {{(MessageDigest) SHA3-224}}
