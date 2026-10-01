from Crypto.Hash import SHA512

hash_sha512 = SHA512.new() # Noncompliant {{(MessageDigest) SHA-512}}
