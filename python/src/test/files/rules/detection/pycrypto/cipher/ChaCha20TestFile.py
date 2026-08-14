from Crypto.Cipher import ChaCha20

key_chacha20 = b"0123456789abcdef0123456789abcdef"
nonce_chacha20 = b"01234567"
cipher_chacha20 = ChaCha20.new(key=key_chacha20, nonce=nonce_chacha20) # Noncompliant {{(StreamCipher) ChaCha20}}
