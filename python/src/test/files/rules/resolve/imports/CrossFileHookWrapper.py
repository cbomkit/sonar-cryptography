from cryptography.hazmat.primitives.asymmetric import ec


# Wrapper defined in a SEPARATE module from its caller. The hook that resolves `arg` is created
# while analyzing THIS file; it must match the `make_private_key(...)` call recorded while analyzing
# the caller module. This is the cross-file leg of the call-stack bucketing path.
def make_private_key(arg):
    return ec.generate_private_key(arg)
