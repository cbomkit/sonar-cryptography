from Crypto.Hash import HMAC

secret = b'some secret'
hmac = HMAC.new(secret) # Noncompliant {{(Mac) HMAC-MD5}}
