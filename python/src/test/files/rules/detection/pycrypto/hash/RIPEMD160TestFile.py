from Crypto.Hash import RIPEMD160

hash_ripemd160 = RIPEMD160.new() # Noncompliant {{(MessageDigest) RIPEMD-160}}
