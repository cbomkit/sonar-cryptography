from Crypto.Hash import SHA512

# SHA512.new(truncate=256) — truncate is an int literal, but the rule declares type "str".
# resolveTreeType resolves the literal statically; the type check rejects the truncate argument.
# The optional truncate param is treated as absent: SHA512 is still detected, but without a
# truncate child.
h = SHA512.new(truncate=256) # Noncompliant {{(MessageDigest) SHA-512}}
