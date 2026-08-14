from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

def generate_cmac(key, data):    
    # Selecting the desired algorithm (e.g., CMAC-AES)
    algorithm = algorithms.AES(key)
    
    # Creating the CMAC context
    cmac_ctx = cmac.CMAC(algorithm) # Noncompliant {{(Mac) CMAC-AES}}
    
    # Updating the context with the data
    cmac_ctx.update(data)
    
    # Finalizing the CMAC computation and getting the CMAC value
    cmac_value = cmac_ctx.finalize()
    
    return cmac_value

# Example usage
if __name__ == "__main__":
    key = b'Sixteen byte key'  # 16-byte key for AES
    data = b'This is some data'  # Data to generate CMAC for
    
    cmac_value = generate_cmac(key, data)
    print("Generated CMAC:", cmac_value.hex())
