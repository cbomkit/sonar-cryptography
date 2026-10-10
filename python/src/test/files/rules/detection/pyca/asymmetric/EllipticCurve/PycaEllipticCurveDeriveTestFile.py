# Code inspired by https://github.com/dimaqq/minioidc/blob/main/tests/test_minioidc.py

import cryptography.hazmat.primitives.asymmetric.ec
import base64

TEST_PRIVATE_KEY = cryptography.hazmat.primitives.asymmetric.ec.derive_private_key( # Noncompliant {{(PrivateKey) EC-secp256r1}}
    int.from_bytes(
        base64.urlsafe_b64decode("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE" + "==="),
        "big",
    ),
    cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
)