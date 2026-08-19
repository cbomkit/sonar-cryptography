from Crypto.Hash import SHA512

# SHA512.new(unknown_kwarg="value") — unknown keyword argument not declared in the rule;
# the call does not match the known SHA512.new signature and must NOT be detected.
h = SHA512.new(unknown_kwarg="value")
