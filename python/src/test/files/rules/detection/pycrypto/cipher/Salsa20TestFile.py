from Crypto.Cipher import Salsa20

key_salsa20 = b"0123456789abcdef0123456789abcdef"
nonce_salsa20 = b"01234567"
cipher_salsa20 = Salsa20.new(key=key_salsa20, nonce=nonce_salsa20) # Noncompliant {{(StreamCipher) Salsa20}}
