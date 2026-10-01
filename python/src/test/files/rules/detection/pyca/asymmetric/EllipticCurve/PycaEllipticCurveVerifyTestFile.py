# Code inspired by https://github.com/redis/redis-py/blob/master/redis/ocsp.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def verify(pubkey, signature, digest):
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        pubkey.verify(signature, digest, ec.ECDSA(hashes.SHA3_512()))
