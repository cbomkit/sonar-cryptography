import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/*
 * setSSLParameters is declared on all three JSSE endpoints. The server socket was already read;
 * these are the client socket and the engine, together with the suites that used to be dropped.
 */
public class SSLSetParametersEndpointsTestFile {

    /* A client socket configured through a parameters object. */
    void clientSocket(SSLSocket socket) {
        SSLParameters parameters = new SSLParameters();
        // Noncompliant@+1 {{(TLS) TLSv1.3}}
        parameters.setProtocols(new String[] { "TLSv1.3" });
        // Noncompliant@+1 {{(TLS) TLS}}
        parameters.setCipherSuites(new String[] { "TLS_RSA_WITH_AES_128_CBC_SHA" });
        socket.setSSLParameters(parameters);
    }

    /* The same for an engine. */
    void engine(SSLEngine engine) {
        SSLParameters parameters = new SSLParameters();
        // Noncompliant@+1 {{(TLS) TLSv1.2}}
        parameters.setProtocols(new String[] { "TLSv1.2" });
        engine.setSSLParameters(parameters);
    }

    /* Counter-check: the parameters come from elsewhere, so nothing about them is knowable. */
    void fromElsewhere(SSLSocket socket, SSLParameters configured) {
        socket.setSSLParameters(configured);
    }
}
