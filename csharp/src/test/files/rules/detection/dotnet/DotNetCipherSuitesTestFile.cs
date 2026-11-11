using System.Collections.Generic;
using System.Net.Security;

/*
 * CipherSuitesPolicy is the only .NET API that names cipher suites directly, and TlsCipherSuite's
 * members are spelled like the IANA registry entries. Shapes modelled on dotnet/runtime's own
 * tests and on real Linux-side TLS hardening code.
 */
public class DotNetCipherSuitesUsage
{
    /* The TLS 1.3 suites, as an array initializer. */
    public CipherSuitesPolicy Tls13Suites()
    {
        return new CipherSuitesPolicy(new[]
        {
            TlsCipherSuite.TLS_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256
        });
    }

    /* A single suite, the narrowest possible policy. */
    public CipherSuitesPolicy OneSuite()
    {
        return new CipherSuitesPolicy(new[] { TlsCipherSuite.TLS_AES_128_GCM_SHA256 });
    }

    /* The explicit element type, and a TLS 1.2 ECDHE suite. */
    public CipherSuitesPolicy Tls12Suite()
    {
        return new CipherSuitesPolicy(
            new TlsCipherSuite[] { TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 });
    }

    /* Assigned onto the authentication options, which is how it reaches a handshake. */
    public SslClientAuthenticationOptions OnClientOptions(string host)
    {
        return new SslClientAuthenticationOptions
        {
            TargetHost = host,
            CipherSuitesPolicy = new CipherSuitesPolicy(new[]
            {
                TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            })
        };
    }

    /* A weak suite has to be visible as itself -- that is what an inventory is read for. */
    public CipherSuitesPolicy WeakSuite()
    {
        return new CipherSuitesPolicy(new[] { TlsCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA });
    }

    /* Counter-check: the list comes from elsewhere, so no suite is knowable. */
    public CipherSuitesPolicy FromParameter(IEnumerable<TlsCipherSuite> configured)
    {
        return new CipherSuitesPolicy(configured);
    }

    /* Counter-check: a member of a different enum must not become a cipher suite. */
    public CipherSuitesPolicy UnrelatedEnumMember()
    {
        return new CipherSuitesPolicy(new[] { SomeOtherEnum.TLS_SOMETHING_INVENTED });
    }

    /* Counter-check: an unrelated constructor of the same arity on another type. */
    public SomePolicy UnrelatedPolicy()
    {
        return new SomePolicy(new[] { TlsCipherSuite.TLS_AES_128_GCM_SHA256 });
    }
}
