import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

class Auth0JwtAuthTestFile {
    String authenticate(String token, String sharedSecret) {
        // Require the expected issuer and verify the signature before using claims.
        Algorithm algorithm = Algorithm.HMAC256(sharedSecret);
        JWTVerifier verifier = JWT.require(algorithm).withIssuer("https://issuer.example").build();
        DecodedJWT jwt = verifier.verify(token); // Auth: JWT
        return jwt.getSubject();
    }

    DecodedJWT decodeOnly(String token) {
        // Decoding without verification must not produce auth evidence.
        return JWT.decode(token);
    }
}
