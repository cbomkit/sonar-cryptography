from Crypto.Cipher import Blowfish

key_blowfish = b"0123456789abcdef"
cipher_blowfish = Blowfish.new(key_blowfish, Blowfish.MODE_CBC) # Noncompliant {{(BlockCipher) Blowfish-CBC}}
