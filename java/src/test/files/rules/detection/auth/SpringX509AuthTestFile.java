import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;

class SpringX509AuthTestFile {
    X509AuthenticationFilter clientCertificateFilter() {
        // Extract the identity from the client certificate's subject.
        X509AuthenticationFilter filter = new X509AuthenticationFilter(); // Auth: MTLS
        filter.setPrincipalExtractor(certificate -> certificate.getSubjectX500Principal().getName());
        return filter;
    }
}
