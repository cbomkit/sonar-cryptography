from Crypto.Cipher import ARC4

key_arc4 = b"0123456789abcdef"
cipher_arc4 = ARC4.new(key_arc4) # Noncompliant {{(StreamCipher) RC4}}
