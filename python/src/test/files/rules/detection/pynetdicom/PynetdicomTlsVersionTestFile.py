import ssl
from pynetdicom import AE


def protocol_constant():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ae = AE()
    return ae.associate("127.0.0.1", 11112, tls_args=(ctx, "localhost"))  # Noncompliant {{(Protocol) DICOM}}


def protocol_keyword():
    ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_1)
    ae = AE()
    return ae.start_server(("", 11112), ssl_context=ctx)  # Noncompliant {{(Protocol) DICOM}}


def minimum_version():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ae = AE()
    return ae.associate("127.0.0.1", 11112, tls_args=(ctx, "localhost"))  # Noncompliant {{(Protocol) DICOM}}


def minimum_version_server():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ae = AE()
    return ae.start_server(("", 11112), ssl_context=ctx)  # Noncompliant {{(Protocol) DICOM}}


def tls_args_variable():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    args = (ctx, "localhost")
    ae = AE()
    return ae.associate("127.0.0.1", 11112, tls_args=args)  # Noncompliant {{(Protocol) DICOM}}


def inline_context():
    ae = AE()
    return ae.make_server(("", 11112), ssl_context=ssl.SSLContext(ssl.PROTOCOL_TLSv1))  # Noncompliant {{(Protocol) DICOM}}


def default_context():
    ctx = ssl.create_default_context()
    ae = AE()
    return ae.associate("127.0.0.1", 11112, tls_args=(ctx, "localhost"))  # Noncompliant {{(Protocol) DICOM}}


def maximum_only():
    ctx = ssl.create_default_context()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ae = AE()
    return ae.associate("127.0.0.1", 11112, tls_args=(ctx, "localhost"))  # Noncompliant {{(Protocol) DICOM}}


def computed_minimum(version):
    ctx = ssl.create_default_context()
    ctx.minimum_version = version
    ae = AE()
    return ae.associate("127.0.0.1", 11112, tls_args=(ctx, "localhost"))  # Noncompliant {{(Protocol) DICOM}}


def conflicting_minimum():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ae = AE()
    return ae.associate("127.0.0.1", 11112, tls_args=(ctx, "localhost"))  # Noncompliant {{(Protocol) DICOM}}


def conditional_minimum(strict):
    ctx = ssl.create_default_context()
    if strict:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ae = AE()
    return ae.associate("127.0.0.1", 11112, tls_args=(ctx, "localhost"))  # Noncompliant {{(Protocol) DICOM}}


def call_inside_branch(connect):
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ae = AE()
    if connect:
        return ae.associate("127.0.0.1", 11112, tls_args=(ctx, "localhost"))  # Noncompliant {{(Protocol) DICOM}}
