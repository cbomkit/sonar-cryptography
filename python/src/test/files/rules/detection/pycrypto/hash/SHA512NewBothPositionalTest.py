from Crypto.Hash import SHA512

# SHA512.new(b"msg", "256") — both by positional fallback (data→index 0, truncate→index 1)
h = SHA512.new(b"msg", "256") # Noncompliant {{(MessageDigest) SHA-512}}
