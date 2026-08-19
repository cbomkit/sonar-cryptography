from Crypto.Hash import SHA512

# SHA512.update() — wrong method name, should NOT be detected by the SHA512.new rule
h = SHA512.update(b"msg")
