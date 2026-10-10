# Code inspired by https://github.com/ydb-platform/ydb/blob/284b7efb67edcdade0b12c849b7fad40739ad62b/contrib/python/Twisted/py2/twisted/conch/ssh/keys.py#L799

from cryptography.hazmat.primitives.asymmetric import dsa, rsa, padding, ec

_curveTable = {
    b'ecdsa-sha2-nistp256': ec.SECP256R1(),
    b'ecdsa-sha2-nistp384': ec.SECP384R1(),
    b'ecdsa-sha2-nistp521': ec.SECP521R1(),
}

def default_backend():
    global _default_backend

    if _default_backend is None:
        from cryptography.hazmat.backends.openssl.backend import backend

        _default_backend = backend

    return _default_backend

class Key(object):
    @classmethod
    def _fromECComponents(cls, x, y, curve, privateValue=None):
        """
        Build a key from EC components.

        @param x: The affine x component of the public point used for verifying.
        @type x: L{int}

        @param y: The affine y component of the public point used for verifying.
        @type y: L{int}

        @param curve: NIST name of elliptic curve.
        @type curve: L{bytes}

        @param privateValue: The private value.
        @type privateValue: L{int}
        """

        publicNumbers = ec.EllipticCurvePublicNumbers(
            x=x, y=y, curve=_curveTable[curve])
        if privateValue is None:
            # We have public components.
            keyObject = publicNumbers.public_key(default_backend())
        else:
            privateNumbers = ec.EllipticCurvePrivateNumbers(
                private_value=privateValue, public_numbers=publicNumbers)
            keyObject = privateNumbers.private_key(default_backend())

        return cls(keyObject)
    
some_var = b'ecdsa-sha2-nistp256'
Key._fromECComponents(None, None, None, some_var, None)