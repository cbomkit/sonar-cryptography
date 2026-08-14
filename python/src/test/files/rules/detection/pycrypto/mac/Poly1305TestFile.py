from Crypto.Hash import Poly1305

key = b'Sixteen byte key'
mac = Poly1305.new(key) # Noncompliant {{(Mac) Poly1305}}
