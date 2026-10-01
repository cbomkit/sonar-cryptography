from Crypto.Hash import SHAKE128
from Crypto.Protocol.DH import key_agreement, import_x448_public_key, import_x448_private_key

def kdf(x):
        return SHAKE128.new(x).read(32)    # Noncompliant {{(ExtendableOutputFunction) SHAKE128}}

pub_key = import_x448_public_key(b'some 32 bytes public key')
priv_key = import_x448_private_key(b'some 32 bytes private key')

session_key = key_agreement(               # Noncompliant {{(KeyAgreement) x448}}
        kdf=kdf,
        static_priv=priv_key,
        static_pub=pub_key)