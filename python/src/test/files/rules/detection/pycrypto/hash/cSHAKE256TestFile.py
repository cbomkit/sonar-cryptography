from Crypto.Hash import cSHAKE256

hash_t128 = cSHAKE256.new() # Noncompliant {{(ExtendableOutputFunction) cSHAKE256}}
