from Crypto.Hash import SHA512

# SHA512.new(truncate="256") — truncate by keyword, data absent (optional)
h = SHA512.new(truncate="256") # Noncompliant {{(MessageDigest) SHA-512}}
