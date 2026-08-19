from Crypto.Hash import SHA512

# SHA512.new(data=b"msg", truncate="256") — both by keyword name, canonical order
h = SHA512.new(data=b"msg", truncate="256") # Noncompliant {{(MessageDigest) SHA-512}}
