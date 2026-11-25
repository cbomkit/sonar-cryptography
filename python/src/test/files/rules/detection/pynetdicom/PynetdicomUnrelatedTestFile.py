from pynetdicom import AE
from other_lib import AE as OtherAE


def other_library():
    ae = OtherAE()
    return ae.associate("127.0.0.1", 11112, tls_args=(1, 2))


def other_method():
    ae = AE()
    ae.add_requested_context("1.2.840.10008.1.1")
    ae.shutdown()
