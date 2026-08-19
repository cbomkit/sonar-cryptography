from Crypto.Hash import SHA256

# SHA256.new() — different algorithm, should NOT be detected by the SHA512 rule
h = SHA256.new()
