from Crypto.Hash import SHA512

# SHA512.new(b"msg") — data by positional fallback, truncate absent (optional)
h = SHA512.new(b"msg") # Noncompliant {{(MessageDigest) SHA-512}}
