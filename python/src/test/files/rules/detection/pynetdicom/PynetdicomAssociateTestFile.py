import ssl
from pynetdicom import AE


def client_tls_args_keyword():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ae = AE()
    assoc = ae.associate("127.0.0.1", 11112, tls_args=(ctx, "localhost"))  # Noncompliant {{(Protocol) DICOM}}
    return assoc


def client_tls_args_positional():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ae = AE()
    assoc = ae.associate("127.0.0.1", 11112, None, "ANY-SCP", 16382, None, None, (ctx, "localhost"))  # Noncompliant {{(Protocol) DICOM}}
    return assoc


def client_tls_args_variable():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    tls_args = (ctx, "localhost")
    ae = AE()
    assoc = ae.associate("127.0.0.1", 11112, ae_title="STORESCP", tls_args=tls_args)  # Noncompliant {{(Protocol) DICOM}}
    return assoc


def client_without_tls():
    ae = AE()
    assoc = ae.associate("127.0.0.1", 11112)  # Noncompliant {{(Protocol) DICOM}}
    return assoc


def client_tls_none():
    ae = AE()
    assoc = ae.associate("127.0.0.1", 11112, tls_args=None)  # Noncompliant {{(Protocol) DICOM}}
    return assoc


def client_tls_unknown(tls):
    ae = AE()
    assoc = ae.associate("127.0.0.1", 11112, tls_args=tls)  # Noncompliant {{(Protocol) DICOM}}
    return assoc


def client_tls_rebound(ctx):
    tls = (ctx, "localhost")
    tls = None
    ae = AE()
    assoc = ae.associate("127.0.0.1", 11112, tls_args=tls)  # Noncompliant {{(Protocol) DICOM}}
    return assoc
