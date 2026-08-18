from cryptography.fernet import Fernet

def test1():
    key = Fernet.generate_key() # Noncompliant {{(SecretKey) Fernet}}

    def enc(data):
        f = Fernet(key)
        return f.encrypt(data)

def test2():
    key = Fernet.generate_key() # Noncompliant {{(SecretKey) Fernet}}

    def enc(data, time):
        f = Fernet(key)
        return f.encrypt_at_time(data, time)

