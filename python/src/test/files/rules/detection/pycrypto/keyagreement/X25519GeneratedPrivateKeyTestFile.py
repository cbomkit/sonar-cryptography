from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128
from Crypto.Protocol.DH import key_agreement, import_x25519_public_key

def kdf(x):
        return SHAKE128.new(x).read(32)    # Noncompliant {{(ExtendableOutputFunction) SHAKE128}}

pub_key = import_x25519_public_key(b'\xab' * 32)
priv_key = ECC.generate(curve="Curve25519")

session_key = key_agreement(               # Noncompliant {{(KeyAgreement) x25519}}
        kdf=kdf,
        static_priv=priv_key,
        static_pub=pub_key)
