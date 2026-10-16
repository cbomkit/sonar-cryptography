from Crypto.Cipher import CAST

key_cast = b"0123456789abcdef"
cipher_cast = CAST.new(key_cast, CAST.MODE_CBC) # Noncompliant {{(BlockCipher) CAST5-CBC}}
