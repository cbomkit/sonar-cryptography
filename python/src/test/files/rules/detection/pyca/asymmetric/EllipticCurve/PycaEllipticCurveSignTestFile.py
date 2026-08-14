from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils

# param = ec.SECP192R1()
param = ec.SECP384R1()
# private_key, other_var = ec.generate_private_key(param), 42 # TODO: because of TraceSeymbols not yet supporting multi-var assignments, this does not work
private_key = ec.generate_private_key(param) # Noncompliant {{(PrivateKey) EC-secp384r1}}

# Ploys that should not be detected
b = ec.ECDSA(utils.Prehashed(hashes.SHA3_224())) # TODO: The test should pass also when removing "b ="
utils.Prehashed(hashes.SHA3_224())
hashes.SHA3_224()

digest = b"\x00" * 64
sig = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA3_512())))

# TODO: Make it work when uncommented
# pk = private_key.public_key()
# pk.verify(sig, digest, ec.ECDSA(hashes.SHA3_512()))

# GROUND TRUTH (translation)
# 
# PrivateKey EC
#   Signature ECDSA
#       MessageDigest SHA3-512
#       EllipticCurveAlgorithm EC
#           EllipticCurve SECP384R1
#       Sign SIGN
#   EllipticCurveAlgorithm EC
#       EllipticCurve SECP384R1
#       KeyGeneration KEYGENERATION
# PublicKey EC
#     EllipticCurveAlgorithm EC
#         EllipticCurve SECP384R1
#         KeyGeneration KEYGENERATION
# 
