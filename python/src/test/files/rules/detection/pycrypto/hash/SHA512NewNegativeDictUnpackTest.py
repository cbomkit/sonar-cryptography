from Crypto.Hash import SHA512

d = {"data": b"msg", "truncate": "256"}

# SHA512.new(**d) — dict unpacking: contents cannot be statically inspected; must NOT be detected.
h = SHA512.new(**d)
