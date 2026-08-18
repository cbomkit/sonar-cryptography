from Crypto.Protocol.KDF import bcrypt

def test_bcrypt():
    password = b"password"
    salt = b"salt1234567890ab"
    key = bcrypt(password, cost=10, salt=salt) # detected but not mapped
