import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

class SpringSamlAuthTestFile {
    Authentication authenticateResponse(RelyingPartyRegistration registration, String samlResponse) {
        // Authenticate the received response using the configured relying party.
        OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
        Saml2AuthenticationToken token = new Saml2AuthenticationToken(registration, samlResponse);
        return provider.authenticate(token); // Auth: SAML
    }
}
