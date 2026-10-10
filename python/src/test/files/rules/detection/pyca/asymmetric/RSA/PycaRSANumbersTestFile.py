from cryptography.hazmat.primitives.asymmetric.rsa import *
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_from_parameters(
        p, q, d, dmp1, dmq1, iqmp, e, n
) -> RSAPrivateKey:
    """
    Note: from certbot dp is dmp1, dq is dmq1 and qi is iqmp
    """
    public_numbers = RSAPublicNumbers(e, n) # Noncompliant {{(PublicKey) RSA}}
    return RSAPrivateNumbers( # Noncompliant {{(PrivateKey) RSA}}
        p, q, d, dmp1, dmq1, iqmp, public_numbers
    ).private_key(default_backend())
