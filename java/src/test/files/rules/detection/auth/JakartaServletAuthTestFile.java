import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;

class JakartaServletAuthTestFile {
    String currentUser(HttpServletRequest request) {
        // Resolve the container-authenticated user, allowing an anonymous request.
        Principal principal = request.getUserPrincipal(); // Auth: PRINCIPAL
        return principal == null ? "anonymous" : principal.getName();
    }

    String readApiKeyHeaderOnly(HttpServletRequest request) {
        // Reading a credential header alone must not imply authentication.
        return request.getHeader("X-API-Key");
    }
}
