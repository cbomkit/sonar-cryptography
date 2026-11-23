from cryptography.hazmat.primitives.poly1305 import Poly1305

def generate_poly1305(key, data):
    # Create a Poly1305 context with the given key
    poly1305_ctx = Poly1305(key) # Noncompliant {{(Mac) Poly1305}}

    # Update the context with the data
    poly1305_ctx.update(data)

    # Finalize the Poly1305 computation and get the authentication tag
    poly1305_tag = poly1305_ctx.finalize()

    return poly1305_tag

# Example usage
if __name__ == "__main__":
    key = b'Sixteen byte key'  # 16-byte key for Poly1305
    data = b'This is some data'  # Data to generate Poly1305 tag for
    
    poly1305_tag = generate_poly1305(key, data)
    print("Generated Poly1305 Tag:", poly1305_tag.hex())
