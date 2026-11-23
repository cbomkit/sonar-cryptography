import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

class JcaMtlsAuthTestFile {
    void validateClientChain(X509TrustManager trustManager, X509Certificate[] clientChain)
            throws Exception {
        trustManager.checkClientTrusted(clientChain, "RSA"); // Auth: MTLS
    }

    String peerIdentity(SSLSession session) throws SSLPeerUnverifiedException {
        // Use the authenticated peer's identity after a TLS handshake.
        Principal peer = session.getPeerPrincipal(); // Auth: MTLS
        return peer.getName();
    }

    Certificate[] peerCertificates(SSLSession session) throws SSLPeerUnverifiedException {
        return session.getPeerCertificates(); // Auth: MTLS
    }
}
