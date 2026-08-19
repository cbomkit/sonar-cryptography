from Crypto.Hash import SHA512

# SHA512.new(b"msg", truncate="256") — data by positional fallback, truncate by keyword name
h = SHA512.new(b"msg", truncate="256") # Noncompliant {{(MessageDigest) SHA-512}}
