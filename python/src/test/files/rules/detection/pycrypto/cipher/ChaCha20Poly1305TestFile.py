from Crypto.Cipher import ChaCha20_Poly1305

key_chacha20_poly1305 = b"0123456789abcdef0123456789abcdef"
nonce_chacha20_poly1305 = b"01234567"
cipher_chacha20_poly1305 = ChaCha20_Poly1305.new(  # Noncompliant {{(AuthenticatedEncryption) ChaCha20-Poly1305}}
    key=key_chacha20_poly1305,
    nonce=nonce_chacha20_poly1305)
