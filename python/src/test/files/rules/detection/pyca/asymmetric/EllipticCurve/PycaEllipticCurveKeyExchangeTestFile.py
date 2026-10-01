from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Generate a private key for use in the exchange.
server_private_key = ec.generate_private_key( # Noncompliant {{(PrivateKey) EC-secp384r1}}
    ec.SECP384R1()
)

def exchange(public_key):
    shared_key = server_private_key.exchange(
        ec.ECDH(), public_key)
    
    # Perform key derivation. // TODO: How should this key derivation be linked to the private key?
    derived_key = HKDF( # Noncompliant {{(KeyDerivationFunction) HKDF-SHA-256}}
         algorithm=hashes.SHA256(),
         length=32,
         salt=None,
         info=b'handshake data',
     ).derive(shared_key)
    return derived_key