from cryptography.fernet import Fernet, MultiFernet

key1 = Fernet(Fernet.generate_key()) # Noncompliant {{(SecretKey) Fernet}}
key2 = Fernet(Fernet.generate_key()) # Noncompliant {{(SecretKey) Fernet}}

def enc(data):
    return MultiFernet([key1, key2]).encrypt(data)

def dec(data):
    return MultiFernet([key1, key2]).decrypt(data)

#  TODO: When using the following code instead, the depending `encrypt` and `decrypt` are detected twice because the type resolution of `f` does not succeed (so it could be Fernet as well as MultiFernet)

# f = MultiFernet([key1, key2])
# def enc(data):
#     return f.encrypt(data)

# def dec(data):
#     return f.decrypt(data)