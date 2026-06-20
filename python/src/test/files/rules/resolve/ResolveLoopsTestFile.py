from cryptography.hazmat.primitives.asymmetric import ec

l1 = [ec.SECP384R1(), ec.BrainpoolP256R1(), ec.SECP192R1()]
for curve in l1:
    # Known limitation: for-loop iterator variable is not resolved to its
    # concrete curve values, so the engine detects the variable name instead
    ec.generate_private_key(curve) # Noncompliant {{curve}}

i = 0
while i < len(l1):
    # Known limitation: only the first list element is resolved;
    # index-based access and control-flow tracking are not yet supported
    ec.generate_private_key(l1[i]) # Noncompliant {{SECP384R1}}
    i += 1