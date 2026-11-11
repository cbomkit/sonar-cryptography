using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using FellowOakDicom.Network.Tls;

/*
 * Every shape below is taken from real code: MailKit, RabbitMQ's .NET client, Npgsql and
 * fo-dicom. The counter-checks at the end are the forms that must stay silent.
 */
public class DotNetTlsUsage
{
    /* Npgsql: the options object an SslStream handshake is driven with. */
    public SslClientAuthenticationOptions NpgsqlOptions(string host)
    {
        return new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.None
        };
    }

    /* MailKit: a property on the client, written as a flags combination. */
    public void MailKitClientProperty(MailService client)
    {
        client.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
    }

    /* A handler default, single member. */
    public void HandlerDefault(HttpClientHandler handler)
    {
        handler.DefaultSslProtocols = SslProtocols.Tls12;
    }

    /* RabbitMQ: SslOption.Version — an ordinary word, so the enum type has to carry it. */
    public void RabbitSslOption(SslOption ssl)
    {
        ssl.Version = SslProtocols.Tls12;
    }

    /* fo-dicom: the handler that a DICOM association is given. This is where the two rule sets meet. */
    public void DicomInitiatorProtocols()
    {
        var tlsInitiator = new DefaultTlsInitiator { Protocols = SslProtocols.Tls13 };
        var client = DicomClientFactory.Create("pacs.example.org", 2762, tlsInitiator, "SCU", "STORESCP");
    }

    /* The legacy global switch, still common in older services. */
    public void LegacyGlobalSwitch()
    {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
    }

    /* An obsolete version has to be visible as itself, not as a nameless TLS. */
    public void ObsoleteVersion(HttpClientHandler handler)
    {
        handler.SslProtocols = SslProtocols.Ssl3;
    }

    /* The handshake, long overload: fo-dicom calls it exactly like this. */
    public void HandshakeWithVersions(SslStream ssl, string host)
    {
        ssl.AuthenticateAsClient(host, null, SslProtocols.Tls12, false);
    }

    /* The handshake, options overload: MailKit calls it like this. The call is still TLS. */
    public void HandshakeWithOptions(SslStream ssl, SslClientAuthenticationOptions options)
    {
        ssl.AuthenticateAsClient(options);
    }

    /*
     * Counter-check, taken from RabbitMQ: the versions are read off another object. The member
     * access resolves to the name "Version", which is not a member of the enum and must not
     * become a protocol of that name.
     */
    public SslClientAuthenticationOptions VersionsFromAnotherObject(SslOption opts)
    {
        return new SslClientAuthenticationOptions { EnabledSslProtocols = opts.Version };
    }

    /* Counter-check: an ordinary Version property holding something else must stay silent. */
    public void UnrelatedVersion(SomeConfig config)
    {
        config.Version = "1.0";
    }

    /* Counter-check: the versions come from a property, so none may be invented. */
    public void VersionsFromProperty(SslStream ssl, string host, SslProtocols configured)
    {
        ssl.AuthenticateAsClient(host, null, configured, false);
    }

    /* ASP.NET Core's server-side TLS, in the three shapes Kestrel is configured with. */
    public void KestrelDefaults(ListenOptions listenOptions)
    {
        listenOptions.UseHttps();
    }

    public void KestrelWithCertificate(ListenOptions listenOptions, X509Certificate2 certificate)
    {
        listenOptions.UseHttps(certificate);
    }

    /* Configured with a block-bodied lambda, which is how Kestrel is usually written. */
    public void KestrelPinnedVersion(ListenOptions listenOptions)
    {
        listenOptions.UseHttps(httpsOptions =>
        {
            httpsOptions.SslProtocols = SslProtocols.Tls13;
        });
    }

    /* And with an expression-bodied one. */
    public void KestrelPinnedVersionInline(ListenOptions listenOptions)
    {
        listenOptions.UseHttps(httpsOptions => httpsOptions.SslProtocols = SslProtocols.Tls12);
    }
}
