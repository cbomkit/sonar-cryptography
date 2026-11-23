import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.security.SignatureException;
import javax.crypto.SecretKey;

class NimbusJwtAuthTestFile {
    String authenticate(String token, SecretKey verificationKey) throws Exception {
        // Reject an invalid signature before reading the token's subject.
        SignedJWT jwt = SignedJWT.parse(token);
        JWSVerifier verifier = new MACVerifier(verificationKey);
        if (!jwt.verify(verifier)) { // Auth: JWT
            throw new SignatureException("Invalid JWT signature");
        }
        return jwt.getJWTClaimsSet().getSubject();
    }

    String verifyPayload(String token, SecretKey verificationKey) throws Exception {
        // A generic signed JWS uses the same verification API family.
        JWSObject jws = JWSObject.parse(token);
        JWSVerifier verifier = new MACVerifier(verificationKey);
        if (!jws.verify(verifier)) { // Auth: JWT
            throw new SignatureException("Invalid JWS signature");
        }
        return jws.getPayload().toString();
    }

    SignedJWT parseOnly(String token) throws Exception {
        // Parsing a JWT without verification must not produce auth evidence.
        return SignedJWT.parse(token);
    }
}
