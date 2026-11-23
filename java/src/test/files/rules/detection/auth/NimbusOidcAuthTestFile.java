import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

class NimbusOidcAuthTestFile {
    IDTokenClaimsSet validateLogin(IDTokenValidator validator, String idToken, Nonce expectedNonce)
            throws Exception {
        // Validate the parsed ID token against the configured provider and login nonce.
        JWT jwt = JWTParser.parse(idToken);
        return validator.validate(jwt, expectedNonce); // Auth: OAUTH
    }
}
