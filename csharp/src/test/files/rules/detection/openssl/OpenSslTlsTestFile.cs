/*
 * OpenSSL's TLS configuration as C# reaches it.
 *
 * The constants appear in both of the two spellings P/Invoke code uses: as members of a holder
 * class, which openssl-net does (`Native.SSL_OP_NO_TLSv1`), and as C# `const int` fields, which is
 * how a hand-rolled interop layer usually declares them. The first resolves to the member's name
 * and the second through the constant to its number, and both have to land on the same version.
 */

using System;
using System.Runtime.InteropServices;

public class OpenSslTlsUsage
{
    // The version constants as a hand-rolled interop layer declares them, with the values from
    // include/openssl/prov_ssl.h.
    private const int TLS1_VERSION = 0x0301;
    private const int TLS1_1_VERSION = 0x0302;
    private const int TLS1_2_VERSION = 0x0303;
    private const int TLS1_3_VERSION = 0x0304;
    private const int SSL3_VERSION = 0x0300;
    private const int DTLS1_2_VERSION = 0xFEFD;

    [DllImport("libssl")] private static extern IntPtr SSL_CTX_new(IntPtr method);
    [DllImport("libssl")] private static extern IntPtr TLS_client_method();
    [DllImport("libssl")] private static extern int SSL_CTX_set_min_proto_version(IntPtr ctx, int version);

    /* A version-flexible client context: TLS, and no version is stated anywhere. */
    public IntPtr FlexibleClient() => SSL_CTX_new(TLS_client_method());

    /* The deprecated version-locked method: TLS 1.2 and nothing else. */
    public IntPtr LockedToTls12() => Native.SSL_CTX_new(Native.TLSv1_2_method());

    /* The server side of the same. */
    public IntPtr LockedServer() => Native.SSL_CTX_new(Native.TLSv1_1_method());

    /* SSL 3.0 is not TLS, and has to be reported as what it is. */
    public IntPtr Sslv3() => Native.SSL_CTX_new(Native.SSLv3_method());

    /* DTLS, version-flexible and version-locked. */
    public IntPtr Dtls() => Native.SSL_CTX_new(Native.DTLS_method());

    public IntPtr Dtls12() => Native.SSL_CTX_new(Native.DTLSv1_2_method());

    /* Every TLS version constant, as a C# const resolving to its wire value. */
    public void MinimumVersions(IntPtr ctx)
    {
        Native.SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
        Native.SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
        Native.SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        Native.SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        Native.SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION);
        Native.SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    }

    /* The same constants as members of a holder class, which resolve by name instead. */
    public void ByMemberName(IntPtr ctx, IntPtr ssl)
    {
        Native.SSL_CTX_set_max_proto_version(ctx, Ssl.TLS1_3_VERSION);
        Native.SSL_set_min_proto_version(ssl, Ssl.TLS1_2_VERSION);
    }

    /* The TLS 1.2 cipher list, naming one suite. */
    public void CipherList(IntPtr ctx)
    {
        Native.SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384");
    }

    /* Two suites in one list. */
    public void TwoSuites(IntPtr ctx)
    {
        Native.SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384");
    }

    /* The TLS 1.3 path, which takes IANA suite names. */
    public void CipherSuites(IntPtr ctx)
    {
        Native.SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    }

    /* A weak suite, which is exactly what an inventory is read for. */
    public void LegacySuite(IntPtr ctx)
    {
        Native.SSL_CTX_set_cipher_list(ctx, "DES-CBC3-SHA");
    }

    /*
     * The negative form. A TLS context is being configured, which is reported, but the disabled
     * versions are not turned into used ones -- SSL_OP_NO_TLSv1 means TLS 1.0 is refused.
     */
    public void NegativeForm(IntPtr ctx)
    {
        Native.SSL_CTX_set_options(ctx, Native.SSL_OP_NO_SSLv3 | Native.SSL_OP_NO_TLSv1 | Native.SSL_OP_NO_TLSv1_1);
    }

    /* Counter-check: 0 means "whatever this build supports", which names no version. */
    public void AutoVersion(IntPtr ctx)
    {
        Native.SSL_CTX_set_min_proto_version(ctx, 0);
    }

    /* Counter-check: the version arrives in a method parameter. */
    public void VersionFromParameter(IntPtr ctx, int version)
    {
        Native.SSL_CTX_set_min_proto_version(ctx, version);
    }

    /* Counter-check: a constant this plugin does not know. */
    public void UnknownConstant(IntPtr ctx)
    {
        Native.SSL_CTX_set_min_proto_version(ctx, Ssl.TLS1_4_VERSION);
    }

    /* Counter-check: a cipher-list expression is a selector, not a list of suites. */
    public void ListExpression(IntPtr ctx)
    {
        Native.SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5");
    }

    /* Counter-check: an alias names no suite either. */
    public void Alias(IntPtr ctx)
    {
        Native.SSL_CTX_set_cipher_list(ctx, "DEFAULT");
    }

    /* Counter-check: the list is built at run time. */
    public void ListFromParameter(IntPtr ctx, string ciphers)
    {
        Native.SSL_CTX_set_cipher_list(ctx, ciphers);
    }
}
