from Crypto.Hash import CMAC
from Crypto.Cipher import AES

key = b'some key'
cmac = CMAC.new(key, AES) # Noncompliant {{(Mac) CMAC-AES}}
