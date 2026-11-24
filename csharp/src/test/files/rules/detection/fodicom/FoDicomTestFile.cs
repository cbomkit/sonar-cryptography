using FellowOakDicom.Network;
using FellowOakDicom.Network.Client;
using FellowOakDicom.Network;
using FellowOakDicom.Network.Client.Advanced.Connection;
using Microsoft.Extensions.Logging;

/*
 * The shapes fo-dicom consumers actually write. Every line below is modelled on
 * fo-dicom/fo-dicom-samples, where 75 of 77 Create calls state the TLS decision as a literal.
 */
/* A consumer's own handler, to check that the slot is not restricted to fo-dicom's classes. */
public class MyTlsInitiator : ITlsInitiator
{
    public Stream InitiateTls(Stream plainStream, string remoteAddress, int remotePort) => plainStream;
}

public class FoDicomUsage
{
    /* C-Store SCU from the samples: a plain association, no transport security. */
    public void PlainAssociation()
    {
        var client = DicomClientFactory.Create("127.0.0.1", 11112, false, "SCU", "STORESCP");
    }

    /* The same call asking for TLS. */
    public void TlsAssociation()
    {
        var client = DicomClientFactory.Create("pacs.example.org", 2762, true, "SCU", "STORESCP");
    }

    /* Host and AE titles from fields, the TLS decision still written out. */
    public void FieldsButLiteralTls(string host, int port, string callingAe, string calledAe)
    {
        var client = DicomClientFactory.Create(host, port, false, callingAe, calledAe);
    }

    /*
     * Counter-check, the sibling overload with the initiator handed in. A non-null initiator is the
     * statement that TLS is on -- fo-dicom's own documentation says TLS is off exactly when it is
     * null -- but a parameter may be null, so this is DICOM with nothing beneath, exactly like the
     * useTls flag handed in as a parameter below.
     */
    public void InitiatorOverload(ITlsInitiator tlsInitiator)
    {
        var client = DicomClientFactory.Create("pacs.example.org", 2762, tlsInitiator, "SCU", "STORESCP");
    }

    /* The form fo-dicom's own tests write: the concrete class, held in a var. TLS. */
    public void ConcreteInitiator()
    {
        var tlsInitiator = new DefaultTlsInitiator();
        var client = DicomClientFactory.Create("pacs.example.org", 2762, tlsInitiator, "SCU", "STORESCP");
    }

    /* Constructed in the argument itself. TLS. */
    public void InlineInitiator()
    {
        var client = DicomClientFactory.Create("pacs.example.org", 2762, new DefaultTlsInitiator(), "SCU", "STORESCP");
    }

    /* Counter-check: a consumer's own initiator class, but handed in, so it may be null. */
    public void OwnInitiator(MyTlsInitiator tlsInitiator)
    {
        var client = DicomClientFactory.Create("pacs.example.org", 2762, tlsInitiator, "SCU", "STORESCP");
    }

    /* A consumer's own initiator class, constructed: the slot is not restricted to fo-dicom's. TLS. */
    public void OwnInitiatorConstructed()
    {
        var client = DicomClientFactory.Create("pacs.example.org", 2762, new MyTlsInitiator(), "SCU", "STORESCP");
    }

    /* A target-typed creation held in a local: the type is not written, but it is an object. TLS. */
    public void TargetTypedInitiator()
    {
        DefaultTlsInitiator tlsInitiator = new();
        var client = DicomClientFactory.Create("pacs.example.org", 2762, tlsInitiator, "SCU", "STORESCP");
    }

    /* Counter-check: a local holding null is a written null one step removed. */
    public void NullVariable()
    {
        ITlsInitiator tlsInitiator = null;
        var client = DicomClientFactory.Create("pacs.example.org", 2762, tlsInitiator, "SCU", "STORESCP");
    }

    /* Counter-check: the default literal of a reference type is null. */
    public void DefaultLiteral()
    {
        var client = DicomClientFactory.Create("pacs.example.org", 2762, tlsInitiator: default, "SCU", "STORESCP");
    }

    /* Counter-check: so is default(T). */
    public void DefaultOfType()
    {
        var client = DicomClientFactory.Create("pacs.example.org", 2762, default(ITlsInitiator), "SCU", "STORESCP");
    }

    /* Counter-check: a cast null is still null. */
    public void CastNull()
    {
        var client = DicomClientFactory.Create("pacs.example.org", 2762, (ITlsInitiator)null, "SCU", "STORESCP");
    }

    /*
     * Counter-check: a call result may be null. This one is not, and losing it is a known recall
     * gap -- the engine does not look into what a method returns for this question.
     */
    public void InitiatorFromCall()
    {
        var client = DicomClientFactory.Create("pacs.example.org", 2762, CreateInitiator(), "SCU", "STORESCP");
    }

    private static ITlsInitiator CreateInitiator() => new DefaultTlsInitiator();

    /* Counter-check: a local assigned twice -- here once with null -- holds no single object. */
    public void ReassignedVariable(bool secure)
    {
        ITlsInitiator tlsInitiator = new DefaultTlsInitiator();
        if (!secure)
        {
            tlsInitiator = null;
        }
        var client = DicomClientFactory.Create("pacs.example.org", 2762, tlsInitiator, "SCU", "STORESCP");
    }

    /* Counter-check: a conditional is only an object on one branch. */
    public void ConditionalInitiator(bool secure)
    {
        var client = DicomClientFactory.Create(
            "pacs.example.org", 2762, secure ? new DefaultTlsInitiator() : null, "SCU", "STORESCP");
    }

    /*
     * Counter-check: a written null means TLS is off. It must not read as TLS, and it must not
     * read as TLS by way of the calling AE title sliding into the initiator slot either.
     */
    public void NullInitiator()
    {
        var client = DicomClientFactory.Create("pacs.example.org", 2762, null, "SCU", "STORESCP");
    }

    /* Keyword arguments, written out of the declared order. */
    public void KeywordArguments()
    {
        var client = DicomClientFactory.Create(
            calledAe: "STORESCP", callingAe: "SCU", useTls: true, port: 2762, host: "pacs.example.org");
    }

    /*
     * The constructor behind the factory. No flag overload exists, so the initiator is the only
     * statement there is -- and it is called with all nine arguments.
     */
    public void ConstructorWithInitiator(DicomClientOptions clientOptions,
        DicomServiceOptions serviceOptions, ILoggerFactory loggerFactory,
        IAdvancedDicomClientConnectionFactory advancedFactory)
    {
        var client = new DicomClient("pacs.example.org", 2762, new DefaultTlsInitiator(), "SCU", "STORESCP",
            clientOptions, serviceOptions, loggerFactory, advancedFactory);
    }

    /* Counter-check: the same constructor with the initiator handed in, which may be null. */
    public void ConstructorWithInitiatorParameter(ITlsInitiator tlsInitiator, DicomClientOptions clientOptions,
        DicomServiceOptions serviceOptions, ILoggerFactory loggerFactory,
        IAdvancedDicomClientConnectionFactory advancedFactory)
    {
        var client = new DicomClient("pacs.example.org", 2762, tlsInitiator, "SCU", "STORESCP",
            clientOptions, serviceOptions, loggerFactory, advancedFactory);
    }

    /* The same constructor without transport security. */
    public void ConstructorWithoutTls(DicomClientOptions clientOptions, DicomServiceOptions serviceOptions,
        ILoggerFactory loggerFactory, IAdvancedDicomClientConnectionFactory advancedFactory)
    {
        var client = new DicomClient("127.0.0.1", 11112, null, "SCU", "STORESCP",
            clientOptions, serviceOptions, loggerFactory, advancedFactory);
    }

    /* Counter-check: the decision comes from a method parameter, so none may be invented. */
    public void UnresolvableTls(bool useTls)
    {
        var client = DicomClientFactory.Create("127.0.0.1", 11112, useTls, "SCU", "STORESCP");
    }

    /* --- The listening side. ------------------------------------------------------------- */

    /* A server on the plaintext DICOM port. Nothing accepts TLS, and nothing should claim it. */
    public void PlainServer()
    {
        var server = DicomServerFactory.Create<DicomCEchoProvider>(104);
    }

    /*
     * The port from a field. This is the shape that forbids demanding the port: it sits at index 0
     * in this overload and at index 1 in the other two, so a required port would throw the call
     * away the moment it is not a literal -- and with it the DICOM association.
     */
    public void PlainServerFromField(int port)
    {
        var server = DicomServerFactory.Create<DicomCEchoProvider>(port);
    }

    /*
     * The form fo-dicom's own TLS test writes, and the only TLS server call in fo-dicom and its
     * sample repository: the acceptor as a keyword argument, past a keyword logger. TLS.
     */
    public void TlsServerKeywordAcceptor(string ipAddress, int port, ILogger logger)
    {
        var tlsAcceptor = new DefaultTlsAcceptor("./cert.p12", "pw");
        var server = DicomServerFactory.Create<DicomCEchoProvider, DicomServer<DicomCEchoProvider>>(
            ipAddress, port, logger: logger, tlsAcceptor: tlsAcceptor);
    }

    /* Counter-check: the same call with the acceptor handed in, which may be null. */
    public void TlsServerAcceptorParameter(string ipAddress, int port, ITlsAcceptor tlsAcceptor, ILogger logger)
    {
        var server = DicomServerFactory.Create<DicomCEchoProvider, DicomServer<DicomCEchoProvider>>(
            ipAddress, port, logger: logger, tlsAcceptor: tlsAcceptor);
    }

    /*
     * Positional, in the overload that puts the acceptor straight after the port. The port refuses
     * it because a primitive can never be an acceptor, and it is then the call's only argument of
     * acceptor type, which is what makes it findable without guessing.
     */
    public void TlsServerInlineAcceptor()
    {
        var server = DicomServerFactory.Create<DicomCEchoProvider>(2762, new DefaultTlsAcceptor("./cert.p12", "pw"));
    }

    /*
     * Known gap, kept here so it is visible: an injected factory held in a variable is NOT
     * detected, and this call yields nothing at all -- not even the DICOM association. The C#
     * receiver is matched by its literal text only, never by a variable's declared type
     * (CSharpLanguageTranslation.getInvokedObjectTypeString says why: resolving declared types made
     * instance calls match static-only rules as well). fo-dicom's ASP.NET hosting writes exactly
     * this shape, so the servers it starts are invisible until receiver resolution grows a way to
     * opt in. Widening this rule to ANY receiver is not that way -- "Create" is far too common a
     * method name to claim a DICOM association from.
     */
    public void TlsServerViaInterface(IDicomServerFactory factory, ITlsAcceptor tlsAcceptor)
    {
        var server = factory.Create<DicomCEchoProvider>(2762, tlsAcceptor);
    }

    /*
     * Counter-check: opaque user state, named. It must not be read as an acceptor -- an object and
     * an interface are indistinguishable by type here, so only the keyword keeps them apart.
     */
    public void ServerWithUserState(object counter, ILogger logger)
    {
        var server = DicomServerFactory.Create<DicomCEchoProvider>(104, logger: logger, userState: counter);
    }

    /*
     * The counter-check this rule's parameter order exists for: the third overload takes the user
     * state positionally, exactly where the second takes the acceptor. Nothing here accepts TLS.
     */
    public void ServerWithPositionalUserState(string ipAddress, int port, object state)
    {
        var server = DicomServerFactory.Create<DicomCEchoProvider, DicomServer<DicomCEchoProvider>>(
            ipAddress, port, state);
    }

    /* Counter-check: a written null acceptor is the factory's own way of saying plaintext. */
    public void ServerWithNullAcceptor()
    {
        var server = DicomServerFactory.Create<DicomCEchoProvider>(104, null);
    }

}
