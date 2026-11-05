import jakarta.ws.rs.core.SecurityContext;
import java.security.Principal;

class JakartaJaxRsAuthTestFile {
    String currentUser(SecurityContext securityContext) {
        // Read the identity established by the JAX-RS authentication mechanism.
        Principal principal = securityContext.getUserPrincipal(); // Auth: PRINCIPAL
        return principal == null ? "anonymous" : principal.getName();
    }
}
