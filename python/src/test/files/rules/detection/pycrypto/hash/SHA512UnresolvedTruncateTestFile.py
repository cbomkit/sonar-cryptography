from Crypto.Hash import SHA512


def digest(option):
    return SHA512.new(truncate=option) # Noncompliant {{(MessageDigest) SHA-512}}
