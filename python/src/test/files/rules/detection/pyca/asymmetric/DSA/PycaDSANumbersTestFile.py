from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateNumbers

def generate_dsa_key_from_parameters(
        p, q, g, x, y
) -> dsa.DSAPrivateKey:
    """
    Generates a DSA private key from parameters p, q, g, x, and y.
    """
    public_numbers = dsa.DSAPublicNumbers(y, dsa.DSAParameterNumbers(p, q, g)) # Noncompliant {{(PublicKey) DSA}}
    private_numbers = DSAPrivateNumbers(x, public_numbers) # Noncompliant {{(PrivateKey) DSA}}
    return private_numbers.private_key(default_backend())
