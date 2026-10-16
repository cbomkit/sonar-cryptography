from Crypto.Hash import BLAKE2b

hash_blake2b = BLAKE2b.new() # Noncompliant {{(MessageDigest) BLAKE2b}}
