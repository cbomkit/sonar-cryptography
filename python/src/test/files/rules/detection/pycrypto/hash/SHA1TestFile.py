from Crypto.Hash import SHA1

hash_sha1 = SHA1.new() # Noncompliant {{(MessageDigest) SHA-1}}
