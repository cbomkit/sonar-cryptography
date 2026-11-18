from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.kbkdf import (
   CounterLocation, KBKDFCMAC, Mode
)

label = b"KBKDF CMAC Label"
context = b"KBKDF CMAC Context"

kdf = KBKDFCMAC( # Noncompliant {{(Mac) CMAC-AES}}
    algorithm=algorithms.AES,
    mode=Mode.CounterMode,
    length=32,
    rlen=4,
    llen=4,
    location=CounterLocation.BeforeFixed,
    label=label,
    context=context,
    fixed=None,
)

key = kdf.derive(b"32 bytes long input key material")