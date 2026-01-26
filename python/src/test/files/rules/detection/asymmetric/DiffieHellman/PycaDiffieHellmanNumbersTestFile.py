from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateNumbers

def generate_dh_key_from_parameters(
        p, g, x, y
) -> dh.DHPrivateKey:
    """
    Generates a DH private key from parameters p, g, x, and y.
    """
    public_numbers = dh.DHPublicNumbers(y, p, g) # Noncompliant {{(PublicKey) FFDH}}
    private_numbers = DHPrivateNumbers(x, public_numbers) # Noncompliant {{(PublicKey) FFDH}}
    return private_numbers.private_key(default_backend())
