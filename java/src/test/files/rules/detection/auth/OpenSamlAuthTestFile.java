import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureValidator;

class OpenSamlAuthTestFile {
    void validateAssertionSignature(Signature assertionSignature, Credential trustedIdpCredential)
            throws Exception {
        // Check the SAML signature profile before validating against the trusted IdP key.
        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        profileValidator.validate(assertionSignature); // Auth: SAML

        // The trusted credential is supplied by the application's IdP configuration.
        SignatureValidator.validate(assertionSignature, trustedIdpCredential); // Auth: SAML
    }
}
