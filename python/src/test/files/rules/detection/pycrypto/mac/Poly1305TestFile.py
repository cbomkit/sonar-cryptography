from Crypto.Hash import Poly1305
from Crypto.Cipher import AES

key = b'0123456789abcdef0123456789abcdef'
mac = Poly1305.new(key=key, cipher=AES) # Noncompliant {{(Mac) Poly1305}}
