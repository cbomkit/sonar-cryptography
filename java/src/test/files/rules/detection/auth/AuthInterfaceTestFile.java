import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

class AuthInterfaceTestFile {
    Jws<Claims> useJjwt(JwtParser parser, String jws) {
        return parser.parseSignedClaims(jws);
    }

    boolean useNimbus(SignedJWT jwt, JWSVerifier verifier) throws Exception {
        return jwt.verify(verifier);
    }

    DecodedJWT useAuth0(JWTVerifier verifier) {
        return verifier.verify((String) null);
    }

    void useJwtDecoder(JwtDecoder decoder) {
        decoder.decode((String) null);
    }

    void useIntrospector(OpaqueTokenIntrospector introspector) {
        introspector.introspect((String) null);
    }

    void useOidcValidator(IDTokenValidator validator) throws Exception {
        validator.validate((JWT) null, (Nonce) null);
    }

    Principal usePrincipal(HttpServletRequest request) {
        return request.getUserPrincipal();
    }
}
