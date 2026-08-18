from Crypto.Cipher import DES3

key_3des = b"0123456789abcdef01234567"
cipher_3des = DES3.new(key_3des, DES3.MODE_CBC) # Noncompliant {{(BlockCipher) 3DES-CBC}}
