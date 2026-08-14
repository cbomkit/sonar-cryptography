from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes

def generate_hmac(key, data):    
    # Selecting the desired hash algorithm (e.g., SHA-256)
    algorithm = hashes.SHA256()
    
    # Creating the HMAC context
    hmac_ctx = hmac.HMAC(key, algorithm) # Noncompliant {{(Mac) HMAC-SHA-256}}
    
    # Updating the context with the data
    hmac_ctx.update(data)
    
    # Finalizing the HMAC computation and getting the HMAC value
    hmac_value = hmac_ctx.finalize()
    
    return hmac_value

# Example usage
if __name__ == "__main__":
    key = b'SecretKey123'  # Key for HMAC
    data = b'This is some data'  # Data to generate HMAC for
    
    hmac_value = generate_hmac(key, data)
    print("Generated HMAC:", hmac_value.hex())
