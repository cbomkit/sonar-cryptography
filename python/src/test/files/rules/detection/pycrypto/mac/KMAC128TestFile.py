from Crypto.Hash import KMAC128

key = b'Sixteen byte key'
mac = KMAC128.new(key=key) # Noncompliant {{(Mac) KMAC128}}
