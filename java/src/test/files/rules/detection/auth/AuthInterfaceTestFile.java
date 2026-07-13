import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.SecurityContext;
import java.security.Principal;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;

class AuthInterfaceTestFile {
    Jws<Claims> useJjwt(JwtParser parser, String jws) {
        return parser.parseSignedClaims(jws);
    }

    @SuppressWarnings("deprecation")
    Jws<Claims> useJjwtLegacyAlias(JwtParser parser, String jws) {
        return parser.parseClaimsJws(jws);
    }

    // Retighten regression: constructing a parser is not verification and must not be detected.
    JwtParser buildJjwtParserOnly() {
        return Jwts.parser().build();
    }

    boolean useNimbus(SignedJWT jwt, JWSVerifier verifier) throws Exception {
        return jwt.verify(verifier);
    }

    boolean useNimbusJwsObject(JWSObject jws, JWSVerifier verifier) throws Exception {
        return jws.verify(verifier);
    }

    DecodedJWT useAuth0(JWTVerifier verifier) {
        return verifier.verify((String) null);
    }

    void useJwtDecoder(JwtDecoder decoder) {
        decoder.decode((String) null);
    }

    void useReactiveJwtDecoder(ReactiveJwtDecoder decoder) {
        decoder.decode((String) null);
    }

    void useIntrospector(OpaqueTokenIntrospector introspector) {
        introspector.introspect((String) null);
    }

    void useOidcValidator(IDTokenValidator validator) throws Exception {
        validator.validate((JWT) null, (Nonce) null);
    }

    void useSignatureValidator() throws Exception {
        SignatureValidator.validate(null, null);
    }

    void useProfileValidator(SAMLSignatureProfileValidator validator) throws Exception {
        validator.validate(null);
    }

    void useSpringSaml2(OpenSaml4AuthenticationProvider provider) {
        provider.authenticate(null);
    }

    Principal usePrincipal(HttpServletRequest request) {
        return request.getUserPrincipal();
    }

    Principal useJavaxServlet(javax.servlet.http.HttpServletRequest request) {
        return request.getUserPrincipal();
    }

    Principal useJakartaJaxrs(SecurityContext context) {
        return context.getUserPrincipal();
    }

    Principal useJavaxJaxrs(javax.ws.rs.core.SecurityContext context) {
        return context.getUserPrincipal();
    }

    Object useSpringAuthentication(org.springframework.security.core.Authentication authentication) {
        return authentication.getPrincipal();
    }

    Principal usePeerPrincipal(SSLSession session) throws Exception {
        return session.getPeerPrincipal();
    }

    java.security.cert.Certificate[] usePeerCertificates(SSLSession session) throws Exception {
        return session.getPeerCertificates();
    }

    void useTrustManager(X509TrustManager manager, java.security.cert.X509Certificate[] chain)
            throws Exception {
        manager.checkClientTrusted(chain, "RSA");
    }

    org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter
            useX509Filter() {
        return new org.springframework.security.web.authentication.preauth.x509
                .X509AuthenticationFilter();
    }

    org.pac4j.http.client.direct.HeaderClient usePac4jHeaderClient() {
        return new org.pac4j.http.client.direct.HeaderClient();
    }

    org.pac4j.http.client.direct.ParameterClient usePac4jParameterClient() {
        return new org.pac4j.http.client.direct.ParameterClient();
    }

    org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter
            useSpringHeaderFilter() {
        return new org.springframework.security.web.authentication.preauth
                .RequestHeaderAuthenticationFilter();
    }
}
