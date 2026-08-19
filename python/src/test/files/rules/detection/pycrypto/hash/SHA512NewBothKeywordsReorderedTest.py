from Crypto.Hash import SHA512

# SHA512.new(truncate="256", data=b"msg") — both by keyword name, reordered
# truncate comes first but the rule must match both by keyword name regardless of order
h = SHA512.new(truncate="256", data=b"msg") # Noncompliant {{(MessageDigest) SHA-512}}
