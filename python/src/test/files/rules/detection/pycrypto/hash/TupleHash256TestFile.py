from Crypto.Hash import TupleHash256

hash_t256 = TupleHash256.new() # Noncompliant {{(ExtendableOutputFunction) TupleHash256}}
