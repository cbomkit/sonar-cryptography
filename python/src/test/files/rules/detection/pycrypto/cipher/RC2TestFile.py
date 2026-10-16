from Crypto.Cipher import ARC2

key_arc2 = b"0123456789abcdef"
cipher_arc2 = ARC2.new(key_arc2, ARC2.MODE_CBC) # Noncompliant {{(BlockCipher) RC2-CBC}}
