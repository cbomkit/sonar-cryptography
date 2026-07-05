import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;

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

    Principal usePrincipal(HttpServletRequest request) {
        return request.getUserPrincipal();
    }
}
