from cryptography.hazmat.primitives.asymmetric import dh

# Generate some parameters. These can be reused.
parameters = dh.generate_parameters(generator=2, key_size=2048)
# Generate a private key for use in the exchange.
server_private_key = parameters.generate_private_key() # Noncompliant {{(PrivateKey) FFDH}}
