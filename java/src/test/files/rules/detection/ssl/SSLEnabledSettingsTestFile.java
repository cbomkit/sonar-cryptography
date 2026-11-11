import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;

/*
 * The JSSE endpoints an application actually holds. SSLServerSocket already had rules; the client
 * socket and the SSLEngine are the shapes that were invisible, and they are the ones ordinary code
 * and every NIO stack use.
 */
public class SSLEnabledSettingsTestFile {

    /* Hardening a client socket: the single most common JSSE call there is. */
    void clientSocketProtocols() throws IOException {
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
            // Noncompliant@+2 {{(TLS) TLSv1.2}}
            // Noncompliant@+1 {{(TLS) TLSv1.3}}
            socket.setEnabledProtocols(new String[] { "TLSv1.2", "TLSv1.3" });
        }
    }

    /* The suites a client offers. */
    void clientSocketCipherSuites() throws IOException {
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
            // Noncompliant@+1 {{(TLS) TLS}}
            socket.setEnabledCipherSuites(new String[] { "TLS_RSA_WITH_AES_128_CBC_SHA" });
        }
    }

    /* The engine every non-blocking stack drives TLS with. */
    void engineProtocols() throws Exception {
        SSLEngine engine = SSLContext.getDefault().createSSLEngine();
        // Noncompliant@+1 {{(TLS) TLSv1.3}}
        engine.setEnabledProtocols(new String[] { "TLSv1.3" });
    }

    /* A suite that encrypts nothing, offered by an engine. */
    void engineCipherSuites() throws Exception {
        SSLEngine engine = SSLContext.getDefault().createSSLEngine();
        // Noncompliant@+1 {{(TLS) TLS}}
        engine.setEnabledCipherSuites(new String[] { "TLS_RSA_WITH_NULL_SHA" });
    }

    /* The constructor states the suites directly. */
    SSLParameters parametersWithSuites() {
        // Noncompliant@+1 {{(TLS) TLS}}
        return new SSLParameters(new String[] { "TLS_RSA_WITH_3DES_EDE_CBC_SHA" });
    }

    /* And the two-argument form states the suites and the versions at once. */
    SSLParameters parametersWithSuitesAndProtocols() {
        // Noncompliant@+2 {{(TLS) TLS}}
        // Noncompliant@+1 {{(TLS) TLSv1.2}}
        return new SSLParameters(
                new String[] { "TLS_RSA_WITH_AES_256_CBC_SHA" }, new String[] { "TLSv1.2" });
    }

    /* Counter-check: the versions come from configuration, so none may be invented. */
    void protocolsFromConfiguration(SSLSocket socket, String[] configured) {
        socket.setEnabledProtocols(configured);
    }

    /* Counter-check: an SSLServerSocket is covered by its own rules and must not double up here. */
    void plainSocketIsNotTls(java.net.Socket socket) throws IOException {
        socket.setKeepAlive(true);
    }
}
