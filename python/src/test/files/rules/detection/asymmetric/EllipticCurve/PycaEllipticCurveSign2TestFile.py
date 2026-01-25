from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey

private_key = Ed25519PrivateKey.generate() # Noncompliant {{(PrivateKey) Ed25519}}
signature = private_key.sign(b"my authenticated message")
public_key = private_key.public_key()
# Raises InvalidSignature if verification fails
public_key.verify(signature, b"my authenticated message")

private_key = Ed448PrivateKey.generate() # Noncompliant {{(PrivateKey) Ed448}}
signature = private_key.sign(b"my authenticated message")
public_key = private_key.public_key()
# Raises InvalidSignature if verification fails
public_key.verify(signature, b"my authenticated message")

# GROUND TRUTH (translation of the 1st finding)
# 
# PrivateKey EC
#   Signature EdDSA
#       MessageDigest SHA-512
#       EllipticCurveAlgorithm EC
#           EllipticCurve Curve25519
#       Sign SIGN
#   EllipticCurveAlgorithm EC
#       EllipticCurve Curve25519
#       KeyGeneration KEYGENERATION
# PublicKey EC
#     EllipticCurveAlgorithm EC
#         EllipticCurve Curve25519
#         KeyGeneration KEYGENERATION
# 