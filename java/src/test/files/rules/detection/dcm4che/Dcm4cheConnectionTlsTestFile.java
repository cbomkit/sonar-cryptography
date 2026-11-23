import org.dcm4che3.net.Connection;

/*
 * The shapes dcm4che's own tools write. Both setters are varargs and the tools pass bare literals,
 * so those are the forms that matter; an array turns up when one connection copies another's
 * settings. Several suites in one call are the normal case, and each one has to arrive.
 */
public class Dcm4cheConnectionTlsTestFile {

    /* The suite dcm4che names in its own code, and it encrypts nothing. */
    public void nullCipher(Connection conn) {
        conn.setTlsCipherSuites("SSL_RSA_WITH_NULL_SHA"); // Noncompliant {{(TLS) TLS}}
    }

    public void twoBareSuites(Connection conn) {
        conn.setTlsCipherSuites("SSL_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"); // Noncompliant {{(TLS) TLS}}
    }

    /*
     * The array form, as produced by setTlsCipherSuites(from.getTlsCipherSuites()).
     *
     * A call that offers several suites raises one issue, not one per suite: the issue names the
     * protocol, and the reporter keeps one issue per distinct node. Every suite still reaches the
     * bill of materials, which is what the assertions below check.
     */
    public void arrayOfTwoSuites(Connection conn) {
        conn.setTlsCipherSuites(new String[] {"TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_GCM_SHA256"}); // Noncompliant {{(TLS) TLS}}
    }

    public void oneProtocol(Connection conn) {
        conn.setTlsProtocols("TLSv1.2"); // Noncompliant {{(TLS) TLSv1.2}}
    }

    public void manyProtocols(Connection conn) {
        conn.setTlsProtocols("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"); // Noncompliant {{(TLS) TLS}} {{(TLS) TLSv1.0}} {{(TLS) TLSv1.1}} {{(TLS) TLSv1.2}}
    }

    /*
     * The form a consumer writes: Connection publishes constants for the three suites it names.
     * Their values are the old JSSE spellings, so TLS_RSA_WITH_NULL_SHA is really
     * "SSL_RSA_WITH_NULL_SHA" and only resolves through the alias.
     */
    public void namedConstant(Connection conn) {
        conn.setTlsCipherSuites(Connection.TLS_RSA_WITH_3DES_EDE_CBC_SHA); // Noncompliant {{(TLS) TLS}}
    }

    /* Counter-check: the suites come from outside, so nothing may be reported. */
    public void fromVariable(Connection conn, String[] ciphers) {
        conn.setTlsCipherSuites(ciphers);
    }
}
