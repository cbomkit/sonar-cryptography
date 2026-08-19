from Cryptodome.Hash import SHA512

# Cryptodome variant — SHA512.new(data=b"msg", truncate="256")
h = SHA512.new(data=b"msg", truncate="256") # Noncompliant {{(MessageDigest) SHA-512}}
