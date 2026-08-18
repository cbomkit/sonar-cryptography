from Crypto.Hash import SHA384

hash_sha384 = SHA384.new() # Noncompliant {{(MessageDigest) SHA-384}}
