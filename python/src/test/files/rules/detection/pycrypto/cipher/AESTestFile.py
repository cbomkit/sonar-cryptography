from Crypto.Cipher import AES

key_aes = b"0123456789abcdef"
cipher_aes = AES.new(key_aes, AES.MODE_CBC, b'some init vector') # Noncompliant {{(BlockCipher) AES-CBC}}
cipher_aes.encrypt(b'some message')
