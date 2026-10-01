from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes

def custom_sign(key, data):
    # Custom function with cryptographic operation
    algorithm = hashes.SHA256()
    hmac_obj = hmac.HMAC(key, algorithm)  # Noncompliant {{(Mac) HMAC-SHA-256}}
    hmac_obj.update(data)
    return hmac_obj.finalize()

def non_crypto_function(text):
    # Non-cryptographic function - should not trigger detection
    result = "not crypto: " + text
    return result.upper()

# Example usage
if __name__ == "__main__":
    key = b'SecretKey123'
    data = b'This is some data'
    
    # Cryptographic operation in custom function is detected
    result = custom_sign(key, data)
    print("HMAC Result:", result.hex())
    
    # Non-cryptographic function call does not trigger detection
    text_result = non_crypto_function("hello")
    print("Text Result:", text_result)
