from Crypto.Hash import SHA512

# SHA512.new(data=b"msg") — data by keyword, truncate absent (optional)
h = SHA512.new(data=b"msg") # Noncompliant {{(MessageDigest) SHA-512}}
