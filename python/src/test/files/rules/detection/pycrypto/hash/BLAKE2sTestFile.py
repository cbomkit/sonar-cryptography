from Crypto.Hash import BLAKE2s

hash_blake2s = BLAKE2s.new() # Noncompliant {{(MessageDigest) BLAKE2s}}
