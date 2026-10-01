from Crypto.Hash import KMAC256

key = b'Sixteen byte key'
mac = KMAC256.new(key=key) # Noncompliant {{(Mac) KMAC256}}
