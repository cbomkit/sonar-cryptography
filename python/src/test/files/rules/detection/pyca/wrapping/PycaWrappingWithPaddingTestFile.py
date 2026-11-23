from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding, aes_key_unwrap_with_padding

def aes_key_wrap_example():
    # Generate a key to wrap
    key_to_wrap = b'Sixteen byte key'

    # Generate wrapping key (must be 128, 192, or 256 bits long)
    wrapping_key = b'ABCDEFGHIJKLMNOP'

    # Wrap the key
    wrapped_key = aes_key_wrap_with_padding(wrapping_key, key_to_wrap, default_backend()) # Noncompliant {{(KeyWrap) AES-128}}

    print("Wrapped Key:", wrapped_key.hex())

    # Unwrap the key
    unwrapped_key = aes_key_unwrap_with_padding(wrapping_key, wrapped_key, default_backend())

    print("Unwrapped Key:", unwrapped_key.hex())

    # Ensure that the unwrapped key matches the original key
    assert unwrapped_key == key_to_wrap

if __name__ == "__main__":
    aes_key_wrap_example()
