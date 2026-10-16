from Crypto.Hash import HMAC, SHA256

secret = b'some secret'
hmac = HMAC.new(secret, digestmod=SHA256) # Noncompliant {{(Mac) HMAC-SHA-256}}
