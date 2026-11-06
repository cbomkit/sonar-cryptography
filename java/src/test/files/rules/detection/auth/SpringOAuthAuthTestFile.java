import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

class SpringOAuthAuthTestFile {
    String authenticateJwt(JwtDecoder decoder, String bearerToken) {
        // A configured decoder verifies the token before exposing its subject.
        Jwt jwt = decoder.decode(bearerToken); // Auth: OAUTH
        return jwt.getSubject();
    }

    Object authenticateReactiveJwt(ReactiveJwtDecoder decoder, String bearerToken) {
        // Return the publisher so the caller can subscribe to token validation.
        return decoder.decode(bearerToken); // Auth: OAUTH
    }

    Object authenticateOpaqueToken(OpaqueTokenIntrospector introspector, String bearerToken) {
        return introspector.introspect(bearerToken); // Auth: OAUTH
    }
}
