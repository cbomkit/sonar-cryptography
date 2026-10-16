from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

key = RSA.importKey(open('public.pem').read())
cipher = PKCS1_v1_5.new(key)  # Noncompliant {{(PublicKeyEncryption) RSA}}
