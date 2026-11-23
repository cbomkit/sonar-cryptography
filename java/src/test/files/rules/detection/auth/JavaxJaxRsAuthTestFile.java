import java.security.Principal;
import javax.ws.rs.core.SecurityContext;

class JavaxJaxRsAuthTestFile {
    String currentUser(SecurityContext securityContext) {
        // Cover applications using the legacy JAX-RS namespace.
        Principal principal = securityContext.getUserPrincipal(); // Auth: PRINCIPAL
        return principal == null ? "anonymous" : principal.getName();
    }
}
