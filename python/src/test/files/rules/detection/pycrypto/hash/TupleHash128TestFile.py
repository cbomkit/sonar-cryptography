from Crypto.Hash import TupleHash128

hash_t128 = TupleHash128.new() # Noncompliant {{(ExtendableOutputFunction) TupleHash}}
