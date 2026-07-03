from cryptography.hazmat.primitives.asymmetric import ec

# Resolve function call returning the entire expression identified by the rule, taking as parameter the parameter to be resolved
def fun6(arg):
    some_var = arg
    return ec.generate_private_key(some_var)
private_key = fun6(ec.SECP384R1()) # Noncompliant {{SECP384R1}}

# Resolve function call returning the entire expression identified by the rule, taking as parameter the parameter to be resolved (this time calling the function in another function)
def fun7(arg7):
    return ec.generate_private_key(arg7)
def fun8():
    private_key = fun7(ec.SECP384R1()) # Noncompliant {{SECP384R1}}
    return private_key

# Cascade of function calls
def fun9(arg):
    return ec.generate_private_key(arg)
def fun10(arg):
    some_var = arg
    return fun9(some_var)
def fun11(arg):
    return fun10(ec.BrainpoolP256R1()) # Noncompliant {{BrainpoolP256R1}}

# Calling a function that has multiple arguments
def fun12(arg1, arg2):
    some_var = arg2
    return ec.generate_private_key(some_var)
private_key = fun12(ec.SECP384R1(), ec.BrainpoolP256R1()) # Noncompliant {{BrainpoolP256R1}}

# Example where the entry point `generate_private_key` is both called by another function and has a parameter that is outputed by another function
def fun13(alg, version) :
    temp = alg
    return temp
def fun14(arg):
    temp = arg
    return ec.generate_private_key(temp)
def fun15():
    algo = ec.SECP384R1()
    private_key = fun14(fun13(algo, 1.3)) # Noncompliant {{SECP384R1}}
    return private_key

# Example where the entry point `generate_private_key` is both called by another function, and directly takes another function as a parameter
def fun16(alg) :
    temp = alg
    return temp
def fun17(arg17):
    return ec.generate_private_key(fun16(arg17))
def fun18():
    private_key = fun17(ec.SECP384R1()) # Noncompliant {{SECP384R1}}
    return private_key

# Resolve an outer parameter that is used as a dictionary subscription index
curve_table = {
    b'ecdsa-sha2-nistp256': ec.SECP256R1(),
    b'ecdsa-sha2-nistp384': ec.SECP384R1(),
    b'ecdsa-sha2-nistp521': ec.SECP521R1(),
}
def fun19(curve):
    return ec.generate_private_key(curve_table[curve])
private_key = fun19(b'ecdsa-sha2-nistp256') # Noncompliant {{SECP256R1}}
