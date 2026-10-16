from Crypto.Hash import SHA224

hash_sha224 = SHA224.new() # Noncompliant {{(MessageDigest) SHA-224}}
