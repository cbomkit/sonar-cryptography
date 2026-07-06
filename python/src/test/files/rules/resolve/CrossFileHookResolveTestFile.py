from cryptography.hazmat.primitives.asymmetric import ec
from imports.CrossFileHookWrapper import make_private_key

# The algorithm literal lives HERE, in the caller module. Cross-file hook resolution must carry it
# into the detection recorded for `generate_private_key` inside CrossFileHookWrapper.py. The issue is
# reported at the resolved value's location (this line), so the Noncompliant marker sits here.
private_key = make_private_key(ec.SECP384R1())  # Noncompliant {{SECP384R1}}
