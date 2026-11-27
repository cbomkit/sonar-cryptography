import ssl
from pynetdicom import AE


def start_server_tls():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ae = AE()
    server = ae.start_server(("127.0.0.1", 11112), block=False, ssl_context=ctx)  # Noncompliant {{(Protocol) DICOM}}
    return server


def start_server_tls_inline():
    ae = AE()
    return ae.start_server(("", 11112), ssl_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))  # Noncompliant {{(Protocol) DICOM}}


def start_server_positional():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ae = AE()
    return ae.start_server(("", 11112), False, ctx)  # Noncompliant {{(Protocol) DICOM}}


def start_server_plain():
    ae = AE()
    return ae.start_server(("127.0.0.1", 11112), block=False)  # Noncompliant {{(Protocol) DICOM}}


def start_server_none():
    ae = AE()
    return ae.start_server(("127.0.0.1", 11112), ssl_context=None)  # Noncompliant {{(Protocol) DICOM}}


def make_server_tls():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ae = AE()
    return ae.make_server(("", 11112), ssl_context=ctx)  # Noncompliant {{(Protocol) DICOM}}


def make_server_plain():
    ae = AE()
    return ae.make_server(("", 11112))  # Noncompliant {{(Protocol) DICOM}}


def make_server_parameter(ctx):
    ae = AE()
    return ae.make_server(("", 11112), ssl_context=ctx)  # Noncompliant {{(Protocol) DICOM}}
