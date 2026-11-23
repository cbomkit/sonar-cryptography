import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import javax.crypto.SecretKey;

class JjwtAuthTestFile {
    String authenticate(String token, SecretKey verificationKey) {
        // Configure verification before accepting claims from a signed token.
        JwtParser parser = Jwts.parser().verifyWith(verificationKey).build();
        Jws<Claims> claims = parser.parseSignedClaims(token); // Auth: JWT
        return claims.getPayload().getSubject();
    }

    @SuppressWarnings("deprecation")
    String authenticateLegacy(String token, SecretKey verificationKey) {
        // Exercise the legacy signed-claims method with the same verification setup.
        JwtParser parser = Jwts.parser().verifyWith(verificationKey).build();
        Jws<Claims> claims = parser.parseClaimsJws(token); // Auth: JWT
        return claims.getBody().getSubject();
    }

    JwtParser configureParserOnly(SecretKey verificationKey) {
        // Parser construction alone must not imply that a token was validated.
        return Jwts.parser().verifyWith(verificationKey).build();
    }
}
