from Crypto.Cipher import DES

key_des = b"01234567"
cipher_des = DES.new(key_des, DES.MODE_ECB) # Noncompliant {{(BlockCipher) DES-56-ECB}}
cipher_des.decrypt(b'some blob')
