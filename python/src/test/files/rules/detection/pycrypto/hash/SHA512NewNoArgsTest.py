from Crypto.Hash import SHA512

# SHA512.new() — no arguments: both data and truncate absent (optional), rule must still match
h = SHA512.new() # Noncompliant {{(MessageDigest) SHA-512}}
