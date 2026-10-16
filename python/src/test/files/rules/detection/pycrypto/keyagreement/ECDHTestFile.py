from Crypto.Hash import SHAKE128
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement

def kdf(x):
        return SHAKE128.new(x).read(32)    # Noncompliant {{(ExtendableOutputFunction) SHAKE128}}

priv_key = ECC.generate(curve='p256')
pub_key = priv_key.public_key()

session_key = key_agreement(               # Noncompliant {{(KeyAgreement) ECDH}}
        kdf=kdf,
        static_priv=priv_key,
        static_pub=pub_key)