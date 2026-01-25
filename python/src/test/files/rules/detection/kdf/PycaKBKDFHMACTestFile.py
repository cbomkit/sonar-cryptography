import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import (
   CounterLocation, KBKDFHMAC, Mode
)

label = b"KBKDF HMAC Label"
context = b"KBKDF HMAC Context"

kdf = KBKDFHMAC( # Noncompliant {{(Mac) HMAC-SHA-256}}
    algorithm=hashes.SHA256(),
    mode=Mode.CounterMode,
    length=32,
    rlen=4,
    llen=4,
    location=CounterLocation.BeforeFixed,
    label=label,
    context=context,
    fixed=None,
)

key = kdf.derive(b"input key")