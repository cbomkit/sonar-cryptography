from Crypto.Hash import SHA512

args = (b"msg", "256")

# SHA512.new(*args) — sequence unpacking: contents cannot be statically inspected; must NOT be detected.
h = SHA512.new(*args)
