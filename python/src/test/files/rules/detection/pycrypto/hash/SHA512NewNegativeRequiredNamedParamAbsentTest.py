from Crypto.Hash import SHA512

# SHA512.new() — truncate is declared as required in this test's rule variant.
# The rule must NOT fire because the required 'truncate' argument is absent.
h = SHA512.new()
