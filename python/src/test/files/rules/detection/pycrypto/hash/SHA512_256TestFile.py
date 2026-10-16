from Crypto.Hash import SHA512

hash_sha512 = SHA512.new(truncate="256") # Noncompliant {{(MessageDigest) SHA-512/256}}
